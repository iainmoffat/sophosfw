# Firewall-side setup

Before sophosfw can talk to a Sophos Firewall, the firewall has to be told
to accept XML API requests, and the user account you'll authenticate as
needs explicit API permission. This is one-time setup per firewall.

If you're connecting to a fresh firewall and getting `auth_failed` (status
534), this is almost certainly the page you need.

## 1. Enable the XML API

The exact menu path moves between firmware versions. Try, in order:

- **Backup & Firmware → API** (most common: Sophos Firewall v19.5+, v20+, v21+, v22+)
- **System → System Services → API** (v17, v18)
- **Administration → API**
- Use the web UI's search bar (top of every page) and type `API` —
  it will jump to the right page regardless of firmware version.

On that page:
- Set **API Configuration** to **Enabled**
- Note the **Allowed IP addresses** list. If it has any entries, your
  laptop's source IP must be in it. If empty, all IPs are allowed.
- Save.

If `nc -z <fw-host> 4444` succeeds and the API is enabled, you have
network reachability. The remaining problem (if any) is authentication.

## 2. Create a dedicated API user (recommended)

You CAN authenticate as the built-in `admin` account, but creating a
dedicated user gives you scoped permissions, audit clarity, and the
option to rotate credentials independently.

**Web UI → Authentication → Users → Add**

- **Username**: `api-sophosfw` (or whatever)
- **User type**: Administrator
- **Profile**: Administrator (full read+write) OR a custom read-only
  profile — see step 3.
- **Group**: usually `Open Group` (default)
- **Password**: see the gotcha in the troubleshooting section below.

Save the user.

## 3. Grant the user API permission

This is the step that's most often missed. Even if a user is an admin
in the web console, that does NOT automatically grant them XML API
access. The XML API permission lives in the **role/profile** assigned
to the user.

**Web UI → System → Profiles** (sometimes "Administration → Profiles")

Find the profile assigned to your API user. Each profile has a
permissions matrix where each row is a feature group and each column
is None / Read-Only / Read-Write.

For sophosfw to work, that profile needs:
- **API access**: enabled (sometimes a discrete row; may be implicit in
  "Web Admin Console" + role permissions on some firmware)
- **Console access** / **Web Admin Console**: at least Read-Only
- The relevant feature rows (Hosts, Services, Firewall, NAT, VPN, etc.)
  set to at least Read-Only for read operations, or Read-Write for
  mutations

The built-in **"Audit Admin"** role grants read-only access to most
feature areas with API access included — a reasonable default for
read-only inspection workflows.

If the profile doesn't have a discrete "API access" row, add the user
to the **API users allowlist** (some firmware versions show this as
a separate sub-tab on the API page from step 1).

## 4. Verify from your laptop

```bash
sophosfw auth profile add prod \
  --url https://<prod-fw-host-or-ip>:4444 \
  --insecure-skip-verify     # drop this if firewall has a real cert

sophosfw auth login --profile prod         # interactive prompt
sophosfw auth test --profile prod --json   # confirm authOk: true
sophosfw object list IPHost --profile prod | head -5   # confirm reads work
```

Expected outcomes per failure mode:

| Result | Likely cause | Fix |
|---|---|---|
| `auth_failed` (534) on `auth login` | Wrong password OR profile lacks API permission | Try web UI login with same creds; if web works, fix profile permissions (step 3) |
| `auth test` passes; `object list IPHost` returns `permission_denied` | Profile has API access but read scope is too narrow | Widen the relevant feature row to Read-Only (step 3) |
| `tls_error` | Self-signed cert with `--insecure-skip-verify` not set | Add `--insecure-skip-verify` to the profile or fix the cert |
| `network_error` | TCP not reachable, or laptop IP not in allowed list | Check `nc -z <host> 4444`; check allowed-IPs list (step 1) |
| 534 on first try, then later attempts also fail even with right password | Account locked from repeated failures | Wait 15-30 min, or unlock via another admin |

## 5. Recommended: mark prod profile read-only

Belt-and-suspenders. Even if your prod admin account is read-only, set
the profile's `readOnly: true` in `~/.config/sophosfw/config.yaml`. The
client-side flag refuses mutations before they ever leave your laptop —
two layers of "no" make accidents harder.

```yaml
profiles:
  prod:
    url: https://sophos01.example.com:4444
    readOnly: true              # ← add this
    insecureSkipVerify: false
    credentialsBackend: keychain
```

To temporarily allow mutations: edit the file, flip to `false`, run
the command, flip back. Slow on purpose.

## Troubleshooting / known gotchas

### Password length limit (silent truncation)

Sophos web UI accepts passwords up to ~64 characters but the XML API
auth path may silently truncate or reject very long passwords. If you
generated a 64+ char password and the firewall's web UI accepts it but
`sophosfw auth login` returns 534 over and over, **rotate to a shorter
password (32-48 chars)** and retry. There is no error message that
points at this — the symptom is "looks accepted, doesn't actually
authenticate".

We hit this in real-world setup; logged here so the next person doesn't.

### "I don't see API under Backup & Firmware"

Sophos has reorganized this menu several times. Use the web UI's
search bar (top right on most builds) and type `API` — it jumps to
the right place regardless of firmware version. See step 1 for the
canonical paths.

### Auth works for full admin but fails for read-only admin

Read-only admin **roles** don't automatically include API access — see
step 3. The profile assigned to the read-only admin needs an explicit
API access permission. The built-in **"Audit Admin"** role is the
shortest path; cloning a profile and ensuring API access is enabled
is the more flexible path.

### Lockout after repeated failures

Sophos throttles auth failures. If you've tried `auth login` 3+ times
in quick succession, wait 15-30 minutes before retrying — even with
the right credentials. Concurrent attempts during the lockout window
can extend the lockout.

### `currentProfile` only points at one firewall

`sophosfw object list IPHost` (no `--profile`) targets the
`currentProfile` from `config.yaml`. When working across multiple
firewalls, always pass `--profile <name>` explicitly. The MCP server
does the same — if the server is started with `--profile prod`, every
tool call defaults to prod unless the call passes its own `profile`
arg.
