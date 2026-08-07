# secretscan

> Scan a directory for committed API keys, tokens and private keys before you push.

## Why

The cheapest moment to catch a committed API key is before the push. This is a
single stdlib-only file you can wire into a pre-commit hook on any machine,
with no service to sign up for.

## Usage

```
python secretscan.py .
python secretscan.py src --min-entropy 3.2    # fewer false positives
python secretscan.py . --show                 # do not redact matches
```

Exit code is 1 when anything is found, so it fails a build or a hook.

## What it looks for

- AWS access key IDs (`AKIA…`, `ASIA…`)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- Slack tokens (`xoxb-`, `xoxp-`, …)
- Google API keys (`AIza…`)
- Stripe live and test keys
- PEM private key blocks
- JWTs
- Assignments like `api_key = "…"` with a long enough value

## Pre-commit hook

`.git/hooks/pre-commit`:

```sh
#!/bin/sh
python /path/to/secretscan.py . || {
  echo "secretscan found something -- commit aborted"
  exit 1
}
```

## Limits

This is a pattern matcher, not a guarantee. It will miss custom credential
formats and it will occasionally flag a long random-looking string that is
harmless. `--min-entropy` trades recall for precision.

Skips `.git`, `node_modules`, virtualenvs, build output, binaries, and files
over 2 MB.

## Tests

```
pip install pytest
pytest
```
