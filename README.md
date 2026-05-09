# 🔍 repo-recon

A Python tool that scans public GitHub repositories for hardcoded secrets, exposed credentials, and sensitive files — then generates a clean, interactive HTML report.

Built for security engineers, developers, and anyone who wants to know what they've accidentally pushed to GitHub.

---

## 📸 What the Report Looks Like

Each finding is displayed in a filterable table. Click any row to expand it and see:

- 🎯 **MITRE ATT&CK** technique mapping (linked to attack.mitre.org)
- 🛡 **OWASP Top 10 (2025)** category (linked to owasp.org)
- 🛠 **Remediation steps** — plain-English instructions on what to do

---

## 🚨 What It Detects

| Category | Examples |
|---|---|
| **API Keys & Tokens** | AWS keys, GitHub tokens, Stripe, Google, Slack, SendGrid, JWT |
| **Passwords** | Hardcoded `password =`, `secret =`, credentials in URLs |
| **Connection Strings** | MySQL, PostgreSQL, MongoDB, Redis, MSSQL URLs |
| **Private Keys & Certs** | RSA/SSH private keys, GCP service account keys |
| **Sensitive Filenames** | `.env`, `id_rsa`, `credentials.json`, `.pem`, `wp-config.php` |

Every finding is rated **CRITICAL / HIGH / MEDIUM / LOW** based on exploitability.

---

## ⚙️ Setup

**Requirements:** Python 3.7+ and `git` (only needed for `--history` scans)

```bash
# 1. Clone this repo
git clone https://github.com/delaney64/repo-recon
cd repo-recon

# 2. Install the one dependency
pip3 install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Scan a single repo
python3 repo_recon.py --repo https://github.com/owner/reponame

# Scan all public repos for a GitHub user or org
python3 repo_recon.py --user someusername

# Scan a list of repos from a text file (one URL per line)
python3 repo_recon.py --file repos.txt

# Also scan git commit history (catches deleted secrets)
python3 repo_recon.py --user someusername --history

# Save the report with a custom filename
python3 repo_recon.py --repo https://github.com/owner/repo --output my_report.html
```

When the scan finishes, open `repo_recon_report.html` in any browser. No server needed.

---

## 📊 Report Features

- **Summary dashboard** — finding counts by severity at a glance
- **Filterable table** — filter by severity, category, or keyword search
- **Expandable rows** — click any finding to see MITRE, OWASP, and remediation
- **Git history tag** — findings from commit history are labeled with their commit hash
- **Self-contained** — the HTML file has no external dependencies, share it anywhere

---

## ⚠️ Rate Limits

This tool uses the **unauthenticated GitHub API**, which allows **60 requests per hour**.

Tips to stay within the limit:
- Test with `--repo` on a single target first
- Avoid scanning very large forked repos (they can have thousands of files)
- Wait a few minutes between full account scans

---

## 🧠 Framework Mappings

Every finding is mapped to:

- **[MITRE ATT&CK](https://attack.mitre.org/)** — adversary technique used to exploit this weakness
- **[OWASP Top 10 (2025)](https://owasp.org/Top10/2025/)** — application security risk category

| Finding Type | MITRE | OWASP |
|---|---|---|
| API keys, passwords, tokens | T1552.001 — Credentials in Files | A07:2025 — Authentication Failures |
| Private keys, certificates | T1552.004 — Private Keys | A04:2025 — Cryptographic Failures |
| Exposed config/env files | T1552.001 — Credentials in Files | A02:2025 — Security Misconfiguration |

---

## ⚖️ Legal & Ethics

> Only scan repositories you own or have **explicit written permission** to test.
> This tool is intended for **authorized security research and defensive purposes only**.
> Unauthorized scanning of systems you do not own may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in other jurisdictions.

---

## 🛠 How It Works

1. **Fetch file tree** — Uses the GitHub Git Trees API to list every file in a repo
2. **Check filenames** — Flags sensitive filenames (`.env`, `id_rsa`, etc.) immediately
3. **Scan content** — Downloads each text file and runs regex patterns against it
4. **Scan history** *(optional)* — Clones the repo locally and scans every commit diff for secrets that may have been added and later "deleted"
5. **Generate report** — Builds a self-contained HTML file with all findings, MITRE/OWASP mappings, and remediation guidance

---

*Built by [@delaney64](https://github.com/delaney64)*
