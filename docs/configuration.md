# Configuration

## File layout

Configuration lives in `~/.config/sophosfw/`:

```
~/.config/sophosfw/
├── config.yaml                 # global settings + profile registry (mode 0600)
└── credentials.yaml            # credentials file backend fallback (mode 0600)
```

## config.yaml schema

```yaml
version: 1
currentProfile: home           # Active profile name
defaults:
  output: table                # "table" or "json"
  timeout: 30s                 # Request timeout
  insecureSkipVerify: false    # TLS verification (global default)
profiles:
  home:                        # Profile name (arbitrary)
    url: https://fw.example.com:4444
    timeout: 30s               # Per-profile override (optional)
    insecureSkipVerify: false  # Reserved for future use
    readOnly: false            # Safety mode: true blocks all mutations at client layer
    apiVersion: ""             # Optional API version pin; empty = firewall decides
    notes: ""                  # User annotations
    credentialsBackend: keychain  # "keychain" (Darwin) or "file" (fallback)
```

## Credential storage

**macOS (Darwin):**
- Backend: `github.com/zalando/go-keyring`
- Service: `sophosfw`
- Account: profile name
- Format: `username\npassword` (newline-delimited, single keychain item per profile)

**Other platforms:**
- Backend: `~/.config/sophosfw/credentials.yaml` (file fallback)
- File mode: `0600`
- Parent dir mode: `0700`
- Verified on read; refuses to load if permissions are looser than 0600

## The `--profile` flag

Override the active profile:
```bash
sophosfw auth status --profile prod --json
```

## Example

Create a profile:
```bash
sophosfw auth profile add home --url https://fw.example.com:4444
sophosfw auth login --profile home              # Prompts for username/password
sophosfw auth status --json                     # Shows current profile
sophosfw auth profile use home                  # Switch active profile
sophosfw auth profile list                      # List all profiles
```

Credentials are stored securely via the platform's credential backend.
