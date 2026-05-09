#!/usr/bin/env python3
"""
repo-recon: A GitHub public repository secret scanner
------------------------------------------------------
Scans public GitHub repos for hardcoded secrets, API keys,
passwords, connection strings, private keys, and sensitive files.

Usage examples:
  python repo_recon.py --repo https://github.com/owner/reponame
  python repo_recon.py --user someusername
  python repo_recon.py --file list_of_repos.txt
  python repo_recon.py --user someusername --history
"""

import re
import sys
import base64
import argparse
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

import requests

from report import generate_report


# ============================================================
# SECTION 1: SECRET PATTERNS
# ------------------------------------------------------------
# Each pattern is a plain dictionary with four keys:
#   "name"     → human-readable label shown in the report
#   "regex"    → the regular expression used to detect the secret
#   "severity" → how dangerous this is: CRITICAL / HIGH / MEDIUM / LOW
#   "category" → grouping label used in the report
#
# Regex cheat sheet for reading these:
#   \s    = any whitespace (space, tab)
#   \w    = any word character (a-z, A-Z, 0-9, _)
#   [=:]  = literally = or :
#   [\'"] = literally a single or double quote
#   {16}  = exactly 16 of the previous character/group
#   {6,}  = 6 or more of the previous character/group
#   (?i)  = case-insensitive (Password = password = PASSWORD)
# ============================================================

PATTERNS = [

    # ── CRITICAL: These are real, specific service credentials ──

    {
        "name": "AWS Access Key ID",
        # AWS access key IDs always start with AKIA followed by 16 uppercase letters/digits
        "regex": r'AKIA[0-9A-Z]{16}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "AWS Secret Access Key",
        # Looks for aws_secret_access_key = "..." with flexible spacing/quotes
        "regex": r'(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "RSA / SSH Private Key Header",
        # Private key files always start with this PEM header
        "regex": r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE KEY',
        "severity": "CRITICAL",
        "category": "Private Keys & Certs",
    },
    {
        "name": "GCP Service Account Key",
        # GCP JSON key files contain this field
        "regex": r'"type"\s*:\s*"service_account"',
        "severity": "CRITICAL",
        "category": "Private Keys & Certs",
    },
    {
        "name": "GitHub Personal Access Token",
        # GitHub's new token format: ghp_, gho_, ghu_, ghs_, ghr_ + 36 chars
        "regex": r'gh[pousr]_[A-Za-z0-9]{36,}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Stripe Secret Key",
        # Live Stripe secret keys start with sk_live_
        "regex": r'sk_live_[A-Za-z0-9]{24,}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Google API Key",
        # Google API keys always start with AIza
        "regex": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Slack Bot / App Token",
        # Slack tokens start with xoxb-, xoxp-, xoxa-, etc.
        "regex": r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },
    {
        "name": "SendGrid API Key",
        # SendGrid keys have a very specific format: SG. + 22 chars + . + 43 chars
        "regex": r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        "severity": "CRITICAL",
        "category": "API Keys & Tokens",
    },

    # ── HIGH: Generic credential patterns ──

    {
        "name": "Hardcoded Password",
        # Matches things like: password = "hunter2" or password: 'abc123'
        "regex": r'(?i)password\s*[=:]\s*[\'"][^\'"]{6,}[\'"]',
        "severity": "HIGH",
        "category": "Passwords",
    },
    {
        "name": "Hardcoded Secret",
        # Matches: secret = "some_value" (at least 8 chars to avoid false positives)
        "regex": r'(?i)\bsecret\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        "severity": "HIGH",
        "category": "Passwords",
    },
    {
        "name": "Hardcoded Token",
        # Matches: token = "long_value_here"
        "regex": r'(?i)\btoken\s*[=:]\s*[\'"][A-Za-z0-9\-._~+/]{16,}[\'"]',
        "severity": "HIGH",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Database Connection String",
        # Matches URLs like: mysql://user:pass@host/db or mongodb://...
        "regex": r'(mysql|postgresql|postgres|mongodb|redis|mssql|jdbc|mariadb)://[^\s\'"<>]+',
        "severity": "HIGH",
        "category": "Connection Strings",
    },
    {
        "name": "Generic Connection String Variable",
        # Matches variable names like connection_string = "..." or connstr = "..."
        "regex": r'(?i)(connection[_\-\s]?string|connstr)\s*[=:]\s*[\'"][^\'"]+[\'"]',
        "severity": "HIGH",
        "category": "Connection Strings",
    },
    {
        "name": "Credentials Embedded in URL",
        # Matches: https://user:password@hostname.com/...
        "regex": r'https?://[^:\s]+:[^@\s]+@[^\s]+',
        "severity": "HIGH",
        "category": "Passwords",
    },

    # ── MEDIUM: Possible secrets, more likely to have false positives ──

    {
        "name": "Generic API Key Variable",
        # Matches: api_key = "longvalue" or apikey = "..."
        "regex": r'(?i)api[_\-]?key\s*[=:]\s*[\'"][A-Za-z0-9\-._]{16,}[\'"]',
        "severity": "MEDIUM",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Bearer Token in Code",
        # Matches: Authorization: Bearer eyJab...
        "regex": r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}',
        "severity": "MEDIUM",
        "category": "API Keys & Tokens",
    },
    {
        "name": "JWT Token",
        # JWTs have three base64 sections separated by dots, first section starts with eyJ
        "regex": r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        "severity": "MEDIUM",
        "category": "API Keys & Tokens",
    },
    {
        "name": "Authorization Header Value",
        # Matches hardcoded Authorization header values in code
        "regex": r'(?i)authorization\s*[=:]\s*[\'"][^\'"]{16,}[\'"]',
        "severity": "MEDIUM",
        "category": "Passwords",
    },
]


# ============================================================
# SECTION 2: SENSITIVE FILENAME PATTERNS
# ------------------------------------------------------------
# Some files are dangerous just by existing in a public repo,
# regardless of what's inside them. We flag these by filename.
#
# Format: (regex_pattern, severity, description)
# ============================================================

SENSITIVE_FILES = [
    (r'(^|/)\.env(\.|$)',           "HIGH",     ".env file — likely contains secrets"),
    (r'(^|/)id_rsa$',               "CRITICAL", "SSH private key"),
    (r'(^|/)id_ed25519$',           "CRITICAL", "SSH private key (Ed25519)"),
    (r'(^|/)id_dsa$',               "CRITICAL", "SSH private key (DSA)"),
    (r'(^|/)credentials\.json$',    "CRITICAL", "GCP credentials file"),
    (r'(^|/)service[_\-]?account\.json$', "CRITICAL", "GCP service account key"),
    (r'(^|/)secrets\.json$',        "HIGH",     "Secrets configuration file"),
    (r'\.pem$',                     "HIGH",     "PEM certificate or key file"),
    (r'\.key$',                     "HIGH",     "Private key file"),
    (r'\.p12$',                     "HIGH",     "PKCS12 certificate file"),
    (r'\.pfx$',                     "HIGH",     "PKCS12 certificate file"),
    (r'\.keystore$',                "HIGH",     "Java keystore file"),
    (r'(^|/)wp-config\.php$',       "HIGH",     "WordPress config — contains DB credentials"),
    (r'(^|/)\.htpasswd$',           "HIGH",     "Apache password file"),
    (r'(^|/)\.netrc$',              "HIGH",     ".netrc — may contain credentials"),
    (r'(^|/)terraform\.tfvars$',    "MEDIUM",   "Terraform vars — may contain secrets"),
    (r'(^|/)database\.yml$',        "MEDIUM",   "Rails database config"),
    (r'(^|/)\.npmrc$',              "MEDIUM",   ".npmrc — may contain auth tokens"),
]


# ============================================================
# SECTION 3: GITHUB API FUNCTIONS
# ------------------------------------------------------------
# The GitHub API lets us read repo contents without cloning.
# All URLs follow the pattern: https://api.github.com/...
# We use the 'requests' library to make HTTP GET calls.
# ============================================================

GITHUB_API = "https://api.github.com"


def get_repos_for_user(username):
    """
    Get a list of all public repos for a GitHub username or org.
    GitHub paginates results (max 100 per page), so we loop until
    we've collected all of them.
    Returns a list of repo dicts from the API.
    """
    repos = []
    page = 1

    while True:
        url = f"{GITHUB_API}/users/{username}/repos"
        # per_page=100 gets the maximum allowed per request
        response = requests.get(url, params={"per_page": 100, "page": page})

        if response.status_code != 200:
            print(f"[!] Could not fetch repos for user '{username}' "
                  f"(HTTP {response.status_code})")
            break

        data = response.json()

        # Empty list means we've gone past the last page
        if not data:
            break

        repos.extend(data)
        page += 1

    return repos


def get_file_tree(owner, repo_name):
    """
    Get a flat list of every file path inside a repo.
    Uses the Git Trees API with recursive=1 to get everything at once.
    Returns a list of file path strings.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo_name}/git/trees/HEAD"
    response = requests.get(url, params={"recursive": "1"})

    if response.status_code != 200:
        print(f"  [!] Could not fetch file tree for {owner}/{repo_name} "
              f"(HTTP {response.status_code})")
        return []

    data = response.json()

    # The API returns a list of tree items. Each item has a "type" field.
    # We only want "blob" items (files), not "tree" items (directories).
    files = [item["path"] for item in data.get("tree", [])
             if item["type"] == "blob"]

    return files


def get_file_content(owner, repo_name, file_path):
    """
    Download and decode the text content of a single file from a repo.
    GitHub returns file content as base64-encoded text, so we decode it.
    Returns the file content as a string, or None if it fails.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{file_path}"
    response = requests.get(url)

    if response.status_code != 200:
        return None

    data = response.json()

    # GitHub encodes file content in base64
    if data.get("encoding") == "base64":
        try:
            # base64.b64decode turns the encoded string back into bytes
            # .decode("utf-8") turns those bytes into a readable string
            # errors="replace" handles any weird characters gracefully
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None

    return None


# ============================================================
# SECTION 4: FILE CONTENT SCANNER
# ------------------------------------------------------------
# These functions apply our patterns to actual file text.
# ============================================================

def scan_file_content(content, file_path, repo_name, in_history=False, commit=None):
    """
    Scan the text of a file against every pattern in PATTERNS.
    Returns a list of finding dicts for any matches found.

    Parameters:
      content    → the raw text of the file
      file_path  → path of the file within the repo (for display)
      repo_name  → name of the repo (for display)
      in_history → True if this match was found in git history
      commit     → the commit hash if found in history
    """
    findings = []

    # Split content into lines so we can report exact line numbers
    lines = content.splitlines()

    for pattern in PATTERNS:
        # Compile the regex pattern (IGNORECASE = case insensitive, MULTILINE = ^ and $ per line)
        regex = re.compile(pattern["regex"], re.IGNORECASE | re.MULTILINE)

        # finditer() returns every match in the content, one by one
        for match in regex.finditer(content):

            # Count newlines before the match position to get the line number
            line_number = content[: match.start()].count("\n") + 1

            # Get the actual line text (strip removes leading/trailing whitespace)
            line_text = ""
            if line_number <= len(lines):
                line_text = lines[line_number - 1].strip()

            findings.append({
                "repo":       repo_name,
                "file":       file_path,
                "line":       line_number,
                "rule":       pattern["name"],
                "severity":   pattern["severity"],
                "category":   pattern["category"],
                "match":      line_text,
                "in_history": in_history,
                "commit":     commit,
            })

    return findings


def check_sensitive_filename(file_path, repo_name):
    """
    Check if a file's path matches any of our sensitive filename patterns.
    Returns a single finding dict if matched, or None if it's fine.
    """
    for pattern_str, severity, description in SENSITIVE_FILES:
        if re.search(pattern_str, file_path, re.IGNORECASE):
            return {
                "repo":       repo_name,
                "file":       file_path,
                "line":       "N/A",
                "rule":       f"Sensitive Filename — {description}",
                "severity":   severity,
                "category":   "Sensitive Filenames",
                "match":      file_path,
                "in_history": False,
                "commit":     None,
            }
    return None


# ============================================================
# SECTION 5: GIT HISTORY SCANNER
# ------------------------------------------------------------
# To scan git history, we need to actually clone the repo locally.
# We use Python's 'subprocess' module to run git commands.
# The clone goes into a temporary folder that auto-deletes when done.
# ============================================================

def scan_git_history(repo_url, repo_name):
    """
    Clone a repo and scan through every commit's changes (the 'diff')
    looking for secrets that may have been added and later deleted.

    This works by running:
      git log --all -p
    which prints every commit and every line that was added (+) or removed (-).
    We only check lines that were ADDED (start with +).

    Returns a list of finding dicts.
    """
    findings = []

    # tempfile.TemporaryDirectory() creates a temp folder and auto-deletes
    # it when the 'with' block ends — no cleanup needed
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"  [*] Cloning {repo_url} for history scan...")

        # Run: git clone <url> <tmpdir>
        # capture_output=True hides the git output from the terminal
        clone_result = subprocess.run(
            ["git", "clone", repo_url, tmpdir],
            capture_output=True,
            text=True
        )

        if clone_result.returncode != 0:
            print(f"  [!] Failed to clone {repo_url}")
            print(f"      {clone_result.stderr.strip()}")
            return findings

        print(f"  [*] Scanning commit history...")

        # Run: git log --all -p --format=COMMIT:<hash>
        # --all    = include every branch, not just main
        # -p       = include the full diff (patch) for each commit
        # --format = print a custom marker line before each commit
        log_result = subprocess.run(
            ["git", "-C", tmpdir, "log", "--all", "-p", "--format=COMMIT:%H"],
            capture_output=True,
            text=True
        )

        # Parse the git log output line by line
        current_commit = None
        current_file = None

        for line in log_result.stdout.splitlines():

            # Track which commit we're currently in
            if line.startswith("COMMIT:"):
                current_commit = line[7:]  # everything after "COMMIT:"

            # Track which file the diff is for
            # Git diff file headers look like: +++ b/path/to/file.py
            elif line.startswith("+++ b/"):
                current_file = line[6:]  # strip the "+++ b/" prefix

            # Only check lines that were ADDED in this commit (start with +)
            # Skip the "+++" header lines (those describe files, not content)
            elif line.startswith("+") and not line.startswith("+++"):
                added_line = line[1:]  # strip the leading + character

                # Check this added line against all patterns
                for pattern in PATTERNS:
                    regex = re.compile(pattern["regex"], re.IGNORECASE)
                    if regex.search(added_line):
                        findings.append({
                            "repo":       repo_name,
                            "file":       current_file or "unknown",
                            "line":       "history",
                            "rule":       pattern["name"],
                            "severity":   pattern["severity"],
                            "category":   pattern["category"],
                            "match":      added_line.strip(),
                            "in_history": True,
                            "commit":     current_commit,
                        })

    return findings


# ============================================================
# SECTION 6: REPO SCANNER — ties everything together
# ------------------------------------------------------------
# This is the main scanning function. It takes a single repo URL,
# fetches all files, checks filenames, scans content, and optionally
# scans history. Returns all findings for that repo.
# ============================================================

def scan_repo(repo_url, scan_history=False):
    """
    Scan a single GitHub repo for secrets.
    Returns a list of findings.

    repo_url looks like: https://github.com/owner/reponame
    """
    findings = []

    # Parse owner and repo name from the URL
    # e.g. "https://github.com/owner/reponame" → ["owner", "reponame"]
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        print(f"[!] Invalid repo URL: {repo_url}")
        return findings

    owner = parts[-2]
    repo_name = parts[-1].replace(".git", "")  # strip .git suffix if present
    full_name = f"{owner}/{repo_name}"

    print(f"\n[*] Scanning {full_name}...")

    # Step 1: Get all file paths in the repo
    file_paths = get_file_tree(owner, repo_name)
    print(f"  [*] Found {len(file_paths)} files")

    # Step 2: Check each file path for sensitive filenames
    for file_path in file_paths:
        filename_finding = check_sensitive_filename(file_path, full_name)
        if filename_finding:
            findings.append(filename_finding)
            print(f"  [!] Sensitive filename: {file_path}")

    # Step 3: Download and scan file content
    # We skip binary-looking files and very large files to save API calls
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".mp4", ".mp3", ".wav", ".zip", ".tar", ".gz", ".pdf",
        ".ttf", ".woff", ".woff2", ".eot", ".otf", ".bin", ".exe",
        ".dll", ".so", ".pyc", ".class",
    }

    for file_path in file_paths:
        # Skip binary file types — they won't contain readable secrets
        ext = Path(file_path).suffix.lower()
        if ext in SKIP_EXTENSIONS:
            continue

        # Wrap the API call in a try/except so a dropped connection or SSL
        # error just skips this file instead of crashing the whole scan
        try:
            content = get_file_content(owner, repo_name, file_path)
        except Exception as e:
            print(f"  [~] Skipping {file_path} ({e})")
            continue
        if content is None:
            continue

        # Skip files over 500KB to avoid huge files killing performance
        if len(content) > 500_000:
            print(f"  [~] Skipping large file: {file_path}")
            continue

        # Scan the content against all patterns
        file_findings = scan_file_content(content, file_path, full_name)
        if file_findings:
            print(f"  [!] {len(file_findings)} finding(s) in {file_path}")
            findings.extend(file_findings)

    # Step 4 (optional): Scan git history
    if scan_history:
        history_findings = scan_git_history(repo_url, full_name)
        if history_findings:
            print(f"  [!] {len(history_findings)} finding(s) in git history")
            findings.extend(history_findings)

    return findings


# ============================================================
# SECTION 7: INPUT PARSERS
# ------------------------------------------------------------
# These functions handle the three different ways to specify repos.
# ============================================================

def repos_from_user(username):
    """Get all public repo URLs for a GitHub username."""
    print(f"[*] Fetching public repos for user: {username}")
    repos = get_repos_for_user(username)
    print(f"[*] Found {len(repos)} public repos")
    # Each repo dict from the API has a "clone_url" field
    return [repo["clone_url"] for repo in repos]


def repos_from_file(filepath):
    """Read a list of repo URLs from a plain text file (one URL per line)."""
    path = Path(filepath)
    if not path.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    lines = path.read_text().strip().splitlines()
    # Filter out blank lines and lines starting with #
    urls = [line.strip() for line in lines
            if line.strip() and not line.strip().startswith("#")]
    print(f"[*] Loaded {len(urls)} repos from {filepath}")
    return urls


# ============================================================
# SECTION 8: MAIN — argument parsing and program entry point
# ============================================================

def main():
    # argparse handles command-line arguments
    # Each add_argument() defines a flag the user can pass
    parser = argparse.ArgumentParser(
        description="repo-recon: Scan public GitHub repos for hardcoded secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python repo_recon.py --repo https://github.com/owner/reponame
  python repo_recon.py --user someusername
  python repo_recon.py --file repos.txt
  python repo_recon.py --user someusername --history
  python repo_recon.py --repo https://github.com/owner/repo --output my_report.html
        """
    )

    # Mutually exclusive group — user must provide exactly one of these
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--repo",
        metavar="URL",
        help="Scan a single repo (e.g. https://github.com/owner/repo)"
    )
    input_group.add_argument(
        "--user",
        metavar="USERNAME",
        help="Scan all public repos for a GitHub username or org"
    )
    input_group.add_argument(
        "--file",
        metavar="FILE",
        help="Scan repos listed in a text file (one URL per line)"
    )

    parser.add_argument(
        "--history",
        action="store_true",  # flag presence = True, absence = False
        help="Also scan git commit history (slower, requires git)"
    )
    parser.add_argument(
        "--output",
        metavar="FILENAME",
        default="repo_recon_report.html",
        help="Output HTML report filename (default: repo_recon_report.html)"
    )

    args = parser.parse_args()

    # ── Build the list of repo URLs to scan ──
    if args.repo:
        repo_urls = [args.repo]
    elif args.user:
        repo_urls = repos_from_user(args.user)
    else:
        repo_urls = repos_from_file(args.file)

    if not repo_urls:
        print("[!] No repos to scan. Exiting.")
        sys.exit(0)

    # ── Scan each repo ──
    all_findings = []
    scan_start = datetime.now()

    for url in repo_urls:
        repo_findings = scan_repo(url, scan_history=args.history)
        all_findings.extend(repo_findings)

    scan_end = datetime.now()
    duration = (scan_end - scan_start).seconds

    # ── Print summary to terminal ──
    print(f"\n{'='*50}")
    print(f"  Scan complete in {duration}s")
    print(f"  Repos scanned : {len(repo_urls)}")
    print(f"  Total findings: {len(all_findings)}")

    # Count by severity
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for f in all_findings if f["severity"] == level)
        if count:
            print(f"  {level:<10}: {count}")

    print(f"{'='*50}")

    # ── Generate the HTML report ──
    report_html = generate_report(
        findings=all_findings,
        repos_scanned=repo_urls,
        scan_date=scan_start.strftime("%Y-%m-%d %H:%M:%S"),
        duration_seconds=duration,
        history_scanned=args.history,
    )

    output_path = Path(args.output)
    output_path.write_text(report_html, encoding="utf-8")
    print(f"\n[+] Report saved to: {output_path.resolve()}")


# Standard Python pattern: only run main() if this script is executed directly
# (not when it's imported by another script)
if __name__ == "__main__":
    main()