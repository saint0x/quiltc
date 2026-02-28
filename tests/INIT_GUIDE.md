# Fozzy Init Guide

This scaffold is set up to run with strict mode by default.
Use `--unsafe` only when intentionally opting out of strict checks.

## Recommended first run
```bash
fozzy full --scenario-root tests --seed 7
```

## Targeted commands
- Run deterministic scenarios: `fozzy test tests/*.fozzy.json --det --json`

Edit the `tests/*.fozzy.json` scenarios with your own inputs and assertions.