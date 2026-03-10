# hushed

Keep secrets out of shell output. A simple CLI secret manager for LLM agents and automation.

[![CI](https://github.com/vadimtitov/hushed/actions/workflows/release.yml/badge.svg)](https://github.com/vadimtitov/hushed/actions/workflows/release.yml)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/vadimtitov/hushed/main/install.sh | bash
```

<details>
<summary>Other install methods</summary>

**Debian / Ubuntu — apt** (one-time repo setup, then upgrades with `apt upgrade`):
```sh
echo "deb [trusted=yes] https://vadimtitov.github.io/hushed/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/hushed.list
sudo apt update && sudo apt install hushed
```

**Go:**
```sh
go install github.com/vadimtitov/hushed/cmd/hushed@latest
```
</details>

## Usage

```sh
# Store a secret (prompts for value, hidden input)
hushed add OPENAI_API_KEY

# Run any command — secrets are injected as env vars, values redacted from output
hushed run -- curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# List stored secret names (never values)
hushed list

# Remove a secret
hushed rm OPENAI_API_KEY
```

Output from `hushed run` has all secret values replaced with `[REDACTED]` in real time — in both stdout and stderr.

## How it works

Secrets are stored encrypted at rest (`~/.hushed/secrets.enc`) using [age](https://age-encryption.org/) encryption. On `hushed run`, secrets are injected into the child process environment and a streaming filter scans the output, replacing any secret value with `[REDACTED]` before it reaches your terminal or logs.

## License

MIT — see [LICENSE](LICENSE).
