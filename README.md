# secretscan

> Scan a directory for committed API keys, tokens and private keys before you push.

## Why

The cheapest moment to catch a committed API key is before the push. This is a
single stdlib-only file you can wire into a pre-commit hook on any machine,
with no service to sign up for.
