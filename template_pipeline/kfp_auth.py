import base64
import hashlib
import json
import logging
import os
import re
import sys
import time
from typing import Optional, Tuple
from urllib.parse import urlencode, urlsplit

import requests
import urllib3
from kubernetes.client import configuration
from requests_oauthlib import OAuth2Session

try:
    # for kubeflow pipelines v2
    from kfp.client.token_credentials_base import TokenCredentialsBase
except ImportError:
    # for kubeflow pipelines v1
    from kfp.auth import TokenCredentialsBase

from kfp import Client


class KFPClientManager:
    """
    A class that creates `kfp.Client` instances with Dex authentication.
    """

    def __init__(
        self,
        api_url: str,
        dex_username: str,
        dex_password: str,
        dex_auth_type: str = "local",
        skip_tls_verify: bool = False,
    ):
        """
        Initialize the KfpClient

        :param api_url: the Kubeflow Pipelines API URL
        :param skip_tls_verify: if True, skip TLS verification
        :param dex_username: the Dex username
        :param dex_password: the Dex password
        :param dex_auth_type: the auth type to use if Dex has multiple enabled,
        one of: ['ldap', 'local']
        """
        self._api_url = api_url
        self._skip_tls_verify = skip_tls_verify
        self._dex_username = dex_username
        self._dex_password = dex_password
        self._dex_auth_type = dex_auth_type
        self._client = None

        # disable SSL verification, if requested
        if self._skip_tls_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # ensure `dex_default_auth_type` is valid
        if self._dex_auth_type not in ["ldap", "local"]:
            raise ValueError(
                f"Invalid `dex_auth_type` '{self._dex_auth_type}'"
                + ", must be one of: ['ldap', 'local']"
            )

    def _get_session_cookies(self) -> str:
        """
        Get the session cookies by authenticating against Dex
        :return: a string of session cookies in the form "key1=value1"
        """

        # use a persistent session (for cookies)
        s = requests.Session()

        # GET the api_url, which should redirect to Dex
        resp = s.get(
            self._api_url,
            allow_redirects=True,
            verify=not self._skip_tls_verify,
        )
        if resp.status_code == 200:
            pass
        elif resp.status_code == 403:
            # if we get 403, we might be at the oauth2-proxy sign-in page
            # the default path to start the sign-in flow is
            # `/oauth2/start?rd=<url>`
            url_obj = urlsplit(resp.url)
            url_obj = url_obj._replace(
                path="/oauth2/start", query=urlencode({"rd": url_obj.path})
            )
            resp = s.get(
                url_obj.geturl(),
                allow_redirects=True,
                verify=not self._skip_tls_verify,
            )
        else:
            raise RuntimeError(
                f"HTTP status code '{resp.status_code}'"
                + "for GET against: {self._api_url}"
            )

        # if we were NOT redirected, then the endpoint is unsecured
        if len(resp.history) == 0:
            # no cookies are needed
            return ""

        # if we are at `/auth?=xxxx` path, we need to select an auth type
        url_obj = urlsplit(resp.url)
        if re.search(r"/auth$", url_obj.path):
            url_obj = url_obj._replace(
                path=re.sub(
                    r"/auth$", f"/auth/{self._dex_auth_type}", url_obj.path
                )
            )

        # if we are at `/auth/xxxx/login` path, then we are at the login page
        if re.search(r"/auth/.*/login$", url_obj.path):
            dex_login_url = url_obj.geturl()
        else:
            # otherwise, we need to follow a redirect to the login page
            resp = s.get(
                url_obj.geturl(),
                allow_redirects=True,
                verify=not self._skip_tls_verify,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"HTTP status code '{resp.status_code}'"
                    + "for GET against: {url_obj.geturl()}"
                )
            dex_login_url = resp.url

        # attempt Dex login
        resp = s.post(
            dex_login_url,
            data={"login": self._dex_username, "password": self._dex_password},
            allow_redirects=True,
            verify=not self._skip_tls_verify,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTTP status code '{resp.status_code}'"
                + "for POST against: {dex_login_url}"
            )

        # if we were NOT redirected, then
        # the login credentials were probably invalid
        if len(resp.history) == 0:
            raise RuntimeError(
                f"Login credentials are probably invalid - "
                f"No redirect after POST to: {dex_login_url}"
            )

        return "; ".join([f"{c.name}={c.value}" for c in s.cookies])

    def _create_kfp_client(self) -> Client:
        try:
            session_cookies = self._get_session_cookies()
        except Exception as ex:
            raise RuntimeError("Failed to get Dex session cookies") from ex

        # monkey patch the kfp.Client to support disabling SSL verification
        # kfp only added support in v2:
        # https://github.com/kubeflow/pipelines/pull/7174
        original_load_config = Client._load_config

        def patched_load_config(client_self, *args, **kwargs):
            config = original_load_config(client_self, *args, **kwargs)
            config.verify_ssl = not self._skip_tls_verify
            return config

        patched_kfp_client = Client
        patched_kfp_client._load_config = patched_load_config

        return patched_kfp_client(
            host=self._api_url,
            cookies=session_cookies,
        )

    def create_kfp_client(self) -> Client:
        """Get a newly authenticated Kubeflow Pipelines client."""
        return self._create_kfp_client()


class DeployKFCredentialsOutOfBand(TokenCredentialsBase):
    """
    A Kubeflow Pipelines credential which uses an "out-of-band" login flow.

    WARNING: intended for deployKF clusters only,
    unlikely to work with other Kubeflow clusters.

    Key features:
     - uses the OIDC client named 'kubeflow-pipelines-sdk'
     - stores tokens in the user's home directory
     - attempts to use the "refresh_token"
       grant before prompting the user to login again
    """

    def __init__(self, issuer_url: str, skip_tls_verify: bool = False):
        """
        Initialize a DeployKFTokenCredentials instance.

        :param issuer_url: the OIDC issuer URL
        :param skip_tls_verify: if True, skip TLS verification
        """
        # oidc configuration
        self.oidc_issuer_url = issuer_url
        self.oidc_client_id = "kubeflow-pipelines-sdk"
        self.oidc_redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
        self.oidc_scope = [
            "openid",
            "email",
            "groups",
            "profile",
            "offline_access",
        ]

        # other configuration
        self.http_timeout = 15
        self.local_credentials_path = os.path.join(
            os.path.expanduser("~"), ".config", "kfp", "dkf_credentials.json"
        )

        # setup logging
        self.log = logging.getLogger(__name__)
        self._setup_logging()

        # disable SSL verification, if requested
        self.skip_tls_verify = skip_tls_verify
        if self.skip_tls_verify:
            self.log.warning("TLS verification is disabled")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        # discover the OIDC issuer configuration
        self._discover_oidc()

        # perform the initial login, if necessary
        self.get_token()

    def _setup_logging(self):
        self.log.propagate = False
        self.log.setLevel(logging.INFO)
        if not self.log.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)-8s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.log.addHandler(handler)

    def _discover_oidc(self):
        """
        Discover the OIDC issuer configuration.
        https://openid.net/specs/openid-connect-discovery-1_0.html
        """
        oidc_discovery_url = (
            f"{self.oidc_issuer_url}/.well-known/openid-configuration"
        )
        self.log.info(
            "Discovering OIDC configuration from: %s", oidc_discovery_url
        )
        response = requests.get(
            url=oidc_discovery_url,
            timeout=self.http_timeout,
            verify=not self.skip_tls_verify,
        )
        response.raise_for_status()
        oidc_issuer_config = response.json()
        self.oidc_issuer = oidc_issuer_config["issuer"]
        self.oidc_auth_endpoint = oidc_issuer_config["authorization_endpoint"]
        self.oidc_token_endpoint = oidc_issuer_config["token_endpoint"]

    def _read_credentials(self) -> dict:
        """
        Read credentials from the JSON file for the current issuer.
        """
        self.log.debug(
            "Checking for existing credentials in: %s",
            self.local_credentials_path,
        )
        if os.path.exists(self.local_credentials_path):
            with open(self.local_credentials_path, "r") as file:
                data = json.load(file)
                return data.get(self.oidc_issuer, {})
        return {}

    def _write_credentials(self, token: str):
        """
        Write the provided token to the local credentials file
        """
        # Create the directory, if it doesn't exist
        credential_dir = os.path.dirname(self.local_credentials_path)
        if not os.path.exists(credential_dir):
            os.makedirs(credential_dir, exist_ok=True)

        # Read all existing credentials from the JSON file
        credentials_data = {}
        # Update the credentials for the given issuer
        credentials_data[self.oidc_issuer] = token
        self.log.info(
            "Writing credentials to: %s", self.local_credentials_path
        )
        with open(self.local_credentials_path, "w") as f:
            json.dump(credentials_data, f)

    def _generate_pkce_verifier(self) -> Tuple[str, str]:
        """
        Generate a PKCE code verifier and its derived challenge.
        https://tools.ietf.org/html/rfc7636#section-4.1
        """
        # Generate a code_verifier of length between 43 and 128 characters
        code_verifier = base64.urlsafe_b64encode(os.urandom(96)).decode(
            "utf-8"
        )
        code_verifier = code_verifier.rstrip("=")
        code_verifier = code_verifier[:128]

        # Generate the code_challenge using the S256 method
        sha256_digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(sha256_digest).decode("utf-8").rstrip("=")
        )

        return code_verifier, code_challenge

    def _refresh_token(self, oauth_session: OAuth2Session) -> Optional[dict]:
        """
        Attempt to refresh the provided token.
        https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens
        """
        if not oauth_session.token.get("refresh_token", None):
            return None

        self.log.warning("Attempting to refresh token...")
        try:
            new_token = oauth_session.refresh_token(
                self.oidc_token_endpoint,
                client_id=self.oidc_client_id,
                timeout=self.http_timeout,
                verify=not self.skip_tls_verify,
            )
            self.log.info("Successfully refreshed token!")
            self._write_credentials(new_token)
            return new_token
        except Exception as ex:
            self.log.error("Failed to refresh token!", exc_info=ex)
        return None

    def _login(self, oauth_session: OAuth2Session) -> dict:
        """
        Start a new "out-of-band" login flow.
        """
        self.log.info("Starting new 'out-of-band' login flow...")

        verifier, challenge = self._generate_pkce_verifier()
        authorization_url, state = oauth_session.authorization_url(
            self.oidc_auth_endpoint,
            code_challenge_method="S256",
            code_challenge=challenge,
        )

        # ensure everything is printed to the console before continuing
        sys.stderr.flush()
        time.sleep(0.5)

        # Get the authorization code from the user
        print(
            "\nPlease open this URL in a browser"
            + f"to continue:\n > {authorization_url}\n",
            flush=True,
        )
        user_input = input("Enter the authorization code:\n > ")
        authorization_code = user_input.strip()

        # Exchange the authorization code for a token
        new_token = oauth_session.fetch_token(
            self.oidc_token_endpoint,
            code=authorization_code,
            code_verifier=verifier,
            include_client_id=True,
            state=state,
            timeout=self.http_timeout,
            verify=not self.skip_tls_verify,
        )
        self.log.info("Successfully fetched new token!")
        self._write_credentials(new_token)
        return new_token

    def get_token(self) -> str:
        """
        Get the current auth token.
        Will attempt to use "refresh_token"
        """
        # return the existing token, if it's valid for at least 5 minutes
        stored_token = self._read_credentials()
        if stored_token:
            expires_at = stored_token.get("expires_at", 0)
            expires_in = expires_at - time.time()
            if expires_in > 300:
                self.log.info(
                    "Using cached auth token (expires in %d seconds)",
                    expires_in,
                )
                return stored_token["id_token"]
            elif expires_in > 0:
                self.log.warning(
                    "Existing auth token expires in %d seconds",
                    expires_in,
                )
            else:
                self.log.warning("Existing auth token has expired!")

        oauth_session = OAuth2Session(
            self.oidc_client_id,
            redirect_uri=self.oidc_redirect_uri,
            scope=self.oidc_scope,
            token=stored_token,
        )

        # try to refresh the token, or start a new login flow
        new_token = self._refresh_token(oauth_session)
        if not new_token:
            new_token = self._login(oauth_session)

        return new_token["id_token"]

    def refresh_api_key_hook(self, config: configuration.Configuration):
        config.verify_ssl = not self.skip_tls_verify
        config.api_key["authorization"] = self.get_token()
