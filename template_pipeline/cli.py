"""CLI interface for template_pipeline project.

Be creative! do whatever you want!

- Install click or typer and create a CLI app
- Use builtin argparse
- Start a web application
- Import things from your .base module
"""

import os

import kfp
from dotenv import load_dotenv

from .kfp_auth import DeployKFCredentialsOutOfBand, KFPClientManager
from .pipeline import pipeline_func


def main():  # pragma: no cover
    """
    The main function executes on commands:
    `python -m template_pipeline` and `$ template_pipeline `.

    This is your program's entry point.

    You can change this function to do whatever you want.
    """
    assert "DEPLOYKF_HOST" in os.environ, "Host of deploykf instance required"
    assert "DEPLOYKF_NS" in os.environ, "Deploykf namespace required"
    deploykf_host = os.environ["DEPLOYKF_HOST"]
    deploykf_namespace = os.environ["DEPLOYKF_NS"]
    deploykf_username = os.environ.get("DEPLOYKF_USER", "")
    deploykf_password = os.environ.get("DEPLOYKF_PW", "")
    use_out_of_band = deploykf_username == "" or deploykf_password == ""

    # initialize a credentials instance and client

    # Security Note: As all deployments are routed through my routers iptable,
    # I am not too concerned about MITM attacks (so lack of ssl encryption is
    # fine for now). If others are connecting over the internet, be sure to
    # Setup https and set "skip_tls_verify" to False
    if use_out_of_band:
        credentials = DeployKFCredentialsOutOfBand(
            issuer_url=deploykf_host + "/dex",
            skip_tls_verify=True,
        )
        kfp_client = kfp.Client(
            host=deploykf_host + "/pipeline",
            verify_ssl=not credentials.skip_tls_verify,
            credentials=credentials,
        )
    else:
        kfp_client_manager = KFPClientManager(
            api_url=deploykf_host,
            skip_tls_verify=True,
            dex_username=deploykf_username,
            dex_password=deploykf_password,
            dex_auth_type="local",
        )
        kfp_client = kfp_client_manager.create_kfp_client()
    load_dotenv()
    # Get definition of experiment/run
    assert "EXPERIMENT" in os.environ, "Name of Experiment required"
    assert "RUN" in os.environ, "Name of run required"
    experiment_name = os.environ["EXPERIMENT"]
    run_name = os.environ["RUN"]
    # Make experiment if it does not exist
    try:
        kfp_client.get_experiment(experiment_name=experiment_name)
    except RuntimeError:
        kfp_client.create_experiment(
            name=experiment_name, namespace=deploykf_namespace
        )
    kfp_client.create_run_from_pipeline_func(
        pipeline_func=pipeline_func,
        arguments={"recipient": "my_recip"},
        experiment_name=experiment_name,
        run_name=run_name,
        namespace=deploykf_namespace,
    )
