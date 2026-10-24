"""echotrail has been renamed to wakeprint.

This shim keeps `import echotrail` and `from echotrail.<module> import ...`
working by aliasing every wakeprint module under the old name.
"""

import importlib
import sys
import warnings

warnings.warn(
    "echotrail has been renamed to wakeprint; install and import 'wakeprint' instead",
    DeprecationWarning,
    stacklevel=2,
)

from wakeprint import *  # noqa: E402,F401,F403
from wakeprint import __all__, __version__  # noqa: E402,F401

for _name in ("anchor", "canonical", "causal", "cli", "export", "mcp_proxy",
              "otel", "recorder", "scan", "server", "siem", "store", "tsr"):
    sys.modules[f"{__name__}.{_name}"] = importlib.import_module(f"wakeprint.{_name}")
