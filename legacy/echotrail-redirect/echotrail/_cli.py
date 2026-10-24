"""`echotrail` command: warns, then runs the `wakeprint` CLI."""

import sys


def main() -> None:
    print("echotrail: renamed to wakeprint; use the 'wakeprint' command instead", file=sys.stderr)
    from wakeprint.cli import main as wakeprint_main

    wakeprint_main()
