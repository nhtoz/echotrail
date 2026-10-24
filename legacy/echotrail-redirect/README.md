# echotrail is now wakeprint

This project has been renamed to **[wakeprint](https://pypi.org/project/wakeprint/)**. Install it directly:

```bash
pip install wakeprint
```

Then replace `echotrail` with `wakeprint` in imports, CLI commands and MCP configs. The trace format is unchanged, so traces, anchors and evidence bundles made with echotrail still verify.

This final `echotrail` release (0.14.0) only installs wakeprint and keeps old code working: `import echotrail` and the `echotrail` command still run, with a deprecation warning. It will not get further updates.

Source: [github.com/nhtoz/wakeprint](https://github.com/nhtoz/wakeprint)
