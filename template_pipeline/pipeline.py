from kfp import dsl

from .components import say_hello


@dsl.pipeline
def pipeline_func(recipient: str) -> str:
    hello_task = say_hello(name=recipient)
    return hello_task.output
