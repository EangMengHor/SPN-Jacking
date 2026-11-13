# ghostSPN

**Read-only Ghost SPN-Jacking exposure inventory** for Active Directory. Enumerates SPNs referenced in `msDS-AllowedToDelegateTo` and compares them with existing `servicePrincipalName` registrations. Unregistered references are flagged for manual review.

> **Scope:** Enumeration only. This tool does not alter Active Directory, verify WriteSPN permissions, request Kerberos tickets, or execute SPN-Jacking. A reported finding is not proof of exploitability.

## Requirements

- Kali Linux or another Linux system (ARM64 / x86_64)
- Python 3.10+
- LDAP connectivity to an authorized Active Directory domain controller

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/ghostSPN.git
cd ghostSPN
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
chmod +x ghostSPN
./ghostSPN --help
```

## Usage

Read-only query of a domain (prompts for the password):

```bash
./ghostSPN -orphaned -d inlanefreight.local --dc-ip DC_IP -u gabriel
```

Include registered SPNs:

```bash
./ghostSPN --all -d inlanefreight.local --dc-ip DC_IP -u gabriel
```

Limit results to one delegation source:

```bash
./ghostSPN -orphaned -d inlanefreight.local --dc-ip DC_IP -u gabriel --delegator 'SRV01$'
```

Export results to JSON:

```bash
./ghostSPN -orphaned -d inlanefreight.local --dc-ip DC_IP -u gabriel --json candidates.json
```

Offline example (does not connect to AD):

```bash
./ghostSPN -orphaned --from-json sample_inventory.json
```

For LDAPS, add `--ldaps`. Certificate validation is enabled by default; `--insecure` is available for test environments with untrusted lab certificates. Use `--simple` only over LDAPS, since simple LDAP bind without TLS can expose a password to network observers. NTLM authentication is the default. For automated use, `GHOSTSPN_PASSWORD` can supply the password; avoid passing `-p` on a shared system because the value may be visible in shell history or process listings.

## Interpreting findings

- `REGISTERED`: Exact SPN exists on an AD account.
- `UNREGISTERED_HOST_ABSENT`: Exact SPN is missing; no matching computer hostname in the collected directory records.
- `UNREGISTERED_HOST_PRESENT`: Exact SPN is missing; the hostname exists as a computer object.
- `UNREGISTERED_NAME_MISMATCH`: Exact SPN is missing; the computer's short hostname matches but the full hostname differs.
- `REVIEW_FORMAT`: Unrecognized SPN format; verify manually.

**Limitations:** This is a proof-of-concept auditor, not a fully validated production scanner. It may miss cross-domain or otherwise inaccessible accounts, aliases, HOST service mappings, or registrations outside the chosen naming context. It does not confirm delegation exploitability or permissions.

## Publish this folder to your GitHub account

Once authenticated with GitHub CLI (`gh auth login`), from this folder:

```bash
git init
git add .
git commit -m "Initial read-only ghostSPN scanner"
gh repo create ghostSPN --public --source=. --remote=origin --push
```

After it has been created, clone from Kali using the URL GitHub prints:

```bash
git clone https://github.com/YOUR_USERNAME/ghostSPN.git
```
