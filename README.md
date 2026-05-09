# 🔍 repo-recon

A Python tool that scans public GitHub repositories for hardcoded secrets, API keys,
passwords, connection strings, private keys, and sensitive files.

Outputs a self-contained HTML report with severity ratings and filtering.

---

## What it detects

| Category | Examples |
|---|---|
| API Keys & Tokens | AWS keys, GitHub tokens, Stripe, Google, Slack, SendGrid |
| Passwords | Hardcoded `password =`, `secret =`, credentials in URLs |
| Connection Strings | MySQL, PostgreSQL, MongoDB, Redis, MSSQL URLs |
| Private Keys & Certs | RSA/SSH private keys, GCP service account keys |
| Sensitive Filenames | `.env`, `id_rsa`, `credentials.json`, `.pem`, `.key` |

---

## Setup

```bash
# Clone this repo
git clone https://github.com/YOUR_USERNAME/repo-recon
cd repo-recon

# Install the one dependency
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan a single repo
python repo_recon.py --repo https://github.com/owner/reponame

# Scan all public repos for a user or org
python repo_recon.py --user someusername

# Scan a list of repos from a file (one URL per line)
python repo_recon.py --file repos.txt

# Include git history scan (slower — requires git installed)
python repo_recon.py --user someusername --history

# Custom output filename
python repo_recon.py --repo https://github.com/owner/repo --output my_report.html
```

---

## Output

An HTML report (`repo_recon_report.html` by default) that includes:

- Summary dashboard with finding counts by severity (Critical / High / Medium / Low)
- Filterable findings table — filter by severity, category, or keyword
- Full match text showing the suspicious line of code
- Git history findings labeled with their commit hash

Open the HTML file in any browser. No server needed.

---

## Rate Limits

This tool uses the unauthenticated GitHub API which allows **60 requests per hour**.
For scanning large orgs or many repos, you may hit this limit.

To stay within the limit:
- Start with `--repo` on a single target
- Avoid running multiple scans in quick succession

---

## Legal / Ethics

Only scan repositories you own or have explicit permission to test.
This tool is for authorized security research and defensive purposes only.

---

## How it works

1. **Fetch file tree** — Uses the GitHub Git Trees API to get every file path in a repo
2. **Check filenames** — Flags sensitive filenames (`.env`, `id_rsa`, etc.) immediately
3. **Scan content** — Downloads each text file and runs regex patterns against it
4. **Scan history** (optional) — Clones the repo locally and scans every commit diff
5. **Generate report** — Builds a self-contained HTML file with all findings
