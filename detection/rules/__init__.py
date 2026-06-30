import inspect
import pkgutil
import importlib

from detection.base_rule import BaseDetectionRule


def load_rules() -> list[BaseDetectionRule]:
    """
    Automatically discovers and instantiates every
    detection rule inside detection.rules.
    """

    rules = []

    package = __name__

    for _, module_name, _ in pkgutil.iter_modules(__path__):

        module = importlib.import_module(
            f"{package}.{module_name}"
        )

        for _, obj in inspect.getmembers(
            module,
            inspect.isclass
        ):

            if (
                issubclass(obj, BaseDetectionRule)
                and obj is not BaseDetectionRule
            ):

                rules.append(obj())

    return rules