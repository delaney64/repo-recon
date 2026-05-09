"""
report.py — HTML Report Generator for repo-recon
-------------------------------------------------
This file has one job: take a list of findings and turn it
into a self-contained HTML file with filtering and styling.

"Self-contained" means all CSS and JavaScript is embedded
directly in the HTML — no internet connection needed to view it.
"""

# We use Python's html module to escape special characters in findings
# so they display correctly in HTML and can't break the page layout.
import html


# ── Severity color definitions ──
# Each severity level gets a background color and text color for its badge.
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#7f1d1d", "text": "#fecaca", "border": "#ef4444"},
    "HIGH":     {"bg": "#7c2d12", "text": "#fed7aa", "border": "#f97316"},
    "MEDIUM":   {"bg": "#713f12", "text": "#fef08a", "border": "#eab308"},
    "LOW":      {"bg": "#14532d", "text": "#bbf7d0", "border": "#22c55e"},
}


def severity_badge(severity):
    """Return an HTML <span> badge styled for the given severity level."""
    colors = SEVERITY_COLORS.get(severity, {"bg": "#374151", "text": "#fff", "border": "#6b7280"})
    return (
        f'<span class="badge" style="'
        f'background:{colors["bg"]};'
        f'color:{colors["text"]};'
        f'border:1px solid {colors["border"]}">'
        f'{severity}</span>'
    )


def escape(text):
    """Safely escape text so it renders as literal text in HTML."""
    if text is None:
        return ""
    return html.escape(str(text))


def generate_report(findings, repos_scanned, scan_date, duration_seconds, history_scanned):
    """
    Build and return a complete HTML report as a string.

    Parameters:
      findings         → list of finding dicts from the scanner
      repos_scanned    → list of repo URLs that were scanned
      scan_date        → datetime string when scan started
      duration_seconds → how long the scan took
      history_scanned  → True if git history was also scanned
    """

    # ── Count findings by severity for the summary dashboard ──
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    # ── Build summary stats cards ──
    summary_cards = f"""
    <div class="stat-card critical">
        <div class="stat-number">{counts['CRITICAL']}</div>
        <div class="stat-label">CRITICAL</div>
    </div>
    <div class="stat-card high">
        <div class="stat-number">{counts['HIGH']}</div>
        <div class="stat-label">HIGH</div>
    </div>
    <div class="stat-card medium">
        <div class="stat-number">{counts['MEDIUM']}</div>
        <div class="stat-label">MEDIUM</div>
    </div>
    <div class="stat-card low">
        <div class="stat-number">{counts['LOW']}</div>
        <div class="stat-label">LOW</div>
    </div>
    <div class="stat-card total">
        <div class="stat-number">{len(findings)}</div>
        <div class="stat-label">TOTAL</div>
    </div>
    """

    # ── Build the repos scanned list ──
    repo_items = "\n".join(
        f'<li><a href="{escape(url)}" target="_blank">{escape(url)}</a></li>'
        for url in repos_scanned
    )

    # ── Build one table row per finding ──
    if findings:
        rows = []
        for i, f in enumerate(findings):
            # Mark history findings so they can be filtered
            history_class = "history-finding" if f.get("in_history") else ""
            history_tag = ""
            if f.get("in_history"):
                commit_short = (f.get("commit") or "")[:8]
                history_tag = (
                    f'<br><span class="history-tag" title="commit {escape(f.get("commit"))}">'
                    f'⏱ git history — {escape(commit_short)}</span>'
                )

            # Build the MITRE detail panel shown when the row is expanded
            mitre_id   = escape(f.get("mitre_id", ""))
            mitre_name = escape(f.get("mitre_name", ""))
            mitre_url  = escape(f.get("mitre_url", ""))
            remediation = escape(f.get("remediation", ""))
            owasp_id   = escape(f.get("owasp_id", ""))
            owasp_name = escape(f.get("owasp_name", ""))
            owasp_url  = escape(f.get("owasp_url", ""))

            mitre_panel = ""
            if mitre_id:
                owasp_block = ""
                if owasp_id:
                    owasp_block = f"""
                                <div class="detail-block">
                                    <div class="detail-label">🛡 OWASP Top 10 (2025)</div>
                                    <div class="detail-value">
                                        <a href="{owasp_url}" target="_blank" class="owasp-link">
                                            {owasp_id}
                                        </a>
                                        &nbsp;—&nbsp;{owasp_name}
                                    </div>
                                </div>"""

                mitre_panel = f"""
                <tr class="detail-row" id="detail-{i}" style="display:none;">
                    <td colspan="8">
                        <div class="detail-panel">
                            <div class="detail-grid">
                                <div class="detail-block">
                                    <div class="detail-label">🎯 MITRE ATT&CK</div>
                                    <div class="detail-value">
                                        <a href="{mitre_url}" target="_blank" class="mitre-link">
                                            {mitre_id}
                                        </a>
                                        &nbsp;—&nbsp;{mitre_name}
                                    </div>
                                </div>
                                {owasp_block}
                                <div class="detail-block">
                                    <div class="detail-label">🛠 Remediation</div>
                                    <div class="detail-value remediation-text">{remediation}</div>
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>"""

            rows.append(f"""
            <tr class="finding-row {history_class}"
                data-severity="{escape(f.get('severity',''))}"
                data-category="{escape(f.get('category',''))}"
                data-index="{i}"
                onclick="toggleDetail({i})"
                style="cursor:pointer;">
                <td>{i + 1} <span class="expand-icon" id="icon-{i}">▶</span></td>
                <td>
                    <a href="https://github.com/{escape(f.get('repo',''))}" target="_blank"
                       onclick="event.stopPropagation()">
                        {escape(f.get('repo',''))}
                    </a>
                </td>
                <td class="file-cell">
                    <code>{escape(f.get('file',''))}</code>
                    {history_tag}
                </td>
                <td>{escape(str(f.get('line','')))}</td>
                <td>{severity_badge(f.get('severity','LOW'))}</td>
                <td><span class="category-tag">{escape(f.get('category',''))}</span></td>
                <td>{escape(f.get('rule',''))}</td>
                <td class="match-cell"><code>{escape(f.get('match',''))}</code></td>
            </tr>
            {mitre_panel}
            """)

        table_body = "\n".join(rows)
    else:
        table_body = """
        <tr>
            <td colspan="9" style="text-align:center; padding:40px; color:#6b7280;">
                No findings detected.
            </td>
        </tr>
        """

    # ── Get unique categories for the filter dropdown ──
    categories = sorted(set(f.get("category", "") for f in findings if f.get("category")))
    category_options = "\n".join(
        f'<option value="{escape(c)}">{escape(c)}</option>'
        for c in categories
    )

    history_note = ""
    if history_scanned:
        history_note = '<span class="history-badge">⏱ Git history included</span>'

    # ── Assemble the full HTML document ──
    # Everything below is the complete HTML page as a Python f-string.
    # The CSS is embedded in <style> tags and the JS in <script> tags.
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>repo-recon Report — {escape(scan_date)}</title>
    <style>
        /* ── Reset & base ── */
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }}

        a {{ color: #60a5fa; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}

        code {{
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.82em;
            background: #1e293b;
            padding: 2px 5px;
            border-radius: 3px;
            color: #fbbf24;
            word-break: break-all;
        }}

        /* ── Header ── */
        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border-bottom: 1px solid #334155;
            padding: 30px 40px;
        }}
        .header h1 {{
            font-size: 1.8em;
            color: #a78bfa;
            letter-spacing: 2px;
            font-weight: 700;
        }}
        .header h1 span {{ color: #60a5fa; }}
        .header .meta {{
            margin-top: 8px;
            font-size: 0.85em;
            color: #64748b;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .history-badge {{
            background: #1e3a5f;
            color: #93c5fd;
            border: 1px solid #3b82f6;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8em;
        }}

        /* ── Main container ── */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 40px;
        }}

        /* ── Summary stats ── */
        .stats-section {{
            margin-bottom: 30px;
        }}
        .stats-section h2 {{
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #64748b;
            margin-bottom: 15px;
        }}
        .stats-grid {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: #1e293b;
            border-radius: 10px;
            padding: 20px 30px;
            text-align: center;
            border: 1px solid #334155;
            min-width: 110px;
        }}
        .stat-card.critical {{ border-color: #ef4444; }}
        .stat-card.high     {{ border-color: #f97316; }}
        .stat-card.medium   {{ border-color: #eab308; }}
        .stat-card.low      {{ border-color: #22c55e; }}
        .stat-card.total    {{ border-color: #8b5cf6; }}
        .stat-number {{
            font-size: 2.2em;
            font-weight: 700;
            font-variant-numeric: tabular-nums;
        }}
        .stat-card.critical .stat-number {{ color: #ef4444; }}
        .stat-card.high     .stat-number {{ color: #f97316; }}
        .stat-card.medium   .stat-number {{ color: #eab308; }}
        .stat-card.low      .stat-number {{ color: #22c55e; }}
        .stat-card.total    .stat-number {{ color: #8b5cf6; }}
        .stat-label {{
            font-size: 0.72em;
            color: #64748b;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            margin-top: 4px;
        }}

        /* ── Repos scanned ── */
        .repos-section {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px 25px;
            margin-bottom: 30px;
        }}
        .repos-section h2 {{
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #64748b;
            margin-bottom: 12px;
        }}
        .repos-section ul {{
            list-style: none;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .repos-section li {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 4px 12px;
            font-size: 0.82em;
        }}

        /* ── Filter controls ── */
        .filters {{
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filters label {{
            font-size: 0.8em;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .filters select, .filters input {{
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 7px 12px;
            font-size: 0.88em;
            outline: none;
        }}
        .filters select:focus, .filters input:focus {{
            border-color: #6366f1;
        }}
        .filters input {{ min-width: 220px; }}
        .filter-count {{
            font-size: 0.82em;
            color: #64748b;
            margin-left: auto;
        }}

        /* ── Findings table ── */
        .table-section h2 {{
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #64748b;
            margin-bottom: 15px;
        }}
        .table-wrapper {{
            overflow-x: auto;
            border-radius: 10px;
            border: 1px solid #334155;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }}
        thead {{
            background: #1e293b;
            border-bottom: 1px solid #334155;
        }}
        th {{
            padding: 12px 14px;
            text-align: left;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.72em;
            letter-spacing: 1px;
            white-space: nowrap;
        }}
        td {{
            padding: 11px 14px;
            border-bottom: 1px solid #1e293b;
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tbody tr {{ background: #0f172a; }}
        tbody tr:nth-child(even) {{ background: #111827; }}
        tbody tr:hover {{ background: #1e293b; }}
        tbody tr.hidden {{ display: none; }}

        .match-cell code {{
            display: block;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #f87171;
        }}
        .match-cell code:hover {{
            white-space: normal;
            word-break: break-all;
        }}

        .file-cell code {{ color: #93c5fd; }}

        .history-tag {{
            display: inline-block;
            margin-top: 4px;
            font-size: 0.75em;
            color: #60a5fa;
            background: #1e3a5f;
            padding: 1px 6px;
            border-radius: 4px;
        }}

        /* ── Severity badge ── */
        .badge {{
            display: inline-block;
            padding: 3px 9px;
            border-radius: 5px;
            font-size: 0.75em;
            font-weight: 700;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}

        /* ── Category tag ── */
        .category-tag {{
            display: inline-block;
            background: #1e293b;
            border: 1px solid #334155;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            color: #94a3b8;
            white-space: nowrap;
        }}

        /* ── No findings ── */
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: #22c55e;
        }}
        .no-findings .icon {{ font-size: 3em; margin-bottom: 15px; }}

        /* ── Footer ── */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #334155;
            font-size: 0.78em;
            border-top: 1px solid #1e293b;
            margin-top: 40px;
        }}

        /* ── Expandable MITRE detail panel ── */
        .expand-icon {{
            font-size: 0.65em;
            color: #475569;
            margin-left: 4px;
            transition: transform 0.2s;
            display: inline-block;
        }}
        .expand-icon.open {{ transform: rotate(90deg); color: #a78bfa; }}

        .detail-row td {{ padding: 0; border-bottom: 1px solid #334155; }}

        .detail-panel {{
            background: #0d1526;
            border-left: 3px solid #6366f1;
            padding: 16px 24px;
            margin: 0;
        }}
        .detail-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr 2fr;
            gap: 16px;
        }}
        @media (max-width: 900px) {{
            .detail-grid {{ grid-template-columns: 1fr 1fr; }}
        }}
        @media (max-width: 600px) {{
            .detail-grid {{ grid-template-columns: 1fr; }}
        }}
        .detail-block {{ display: flex; flex-direction: column; gap: 6px; }}
        .detail-label {{
            font-size: 0.72em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #64748b;
            font-weight: 600;
        }}
        .detail-value {{
            font-size: 0.88em;
            color: #cbd5e1;
            line-height: 1.5;
        }}
        .mitre-link {{
            background: #1e1b4b;
            color: #a78bfa;
            border: 1px solid #4f46e5;
            padding: 2px 10px;
            border-radius: 5px;
            font-weight: 700;
            font-size: 0.9em;
            text-decoration: none;
        }}
        .mitre-link:hover {{ background: #2e2a6e; }}
        .owasp-link {{
            background: #1a2e1a;
            color: #86efac;
            border: 1px solid #22c55e;
            padding: 2px 10px;
            border-radius: 5px;
            font-weight: 700;
            font-size: 0.9em;
            text-decoration: none;
        }}
        .owasp-link:hover {{ background: #14532d; }}
        .remediation-text {{ color: #86efac; }}
    </style>
</head>
<body>

    <!-- ── Header ── -->
    <div class="header">
        <h1>🔍 repo<span>-recon</span></h1>
        <div class="meta">
            <span>📅 {escape(scan_date)}</span>
            <span>⏱ {duration_seconds}s scan time</span>
            <span>📦 {len(repos_scanned)} repo(s) scanned</span>
            {history_note}
        </div>
    </div>

    <div class="container">

        <!-- ── Summary stats ── -->
        <div class="stats-section">
            <h2>Summary</h2>
            <div class="stats-grid">
                {summary_cards}
            </div>
        </div>

        <!-- ── Repos scanned ── -->
        <div class="repos-section">
            <h2>Repos Scanned</h2>
            <ul>
                {repo_items}
            </ul>
        </div>

        <!-- ── Findings table ── -->
        <div class="table-section">
            <h2>Findings</h2>

            <!-- Filter controls — all filtering is done in JavaScript below -->
            <div class="filters">
                <label>Severity</label>
                <select id="filter-severity" onchange="applyFilters()">
                    <option value="">All</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                </select>

                <label>Category</label>
                <select id="filter-category" onchange="applyFilters()">
                    <option value="">All</option>
                    {category_options}
                </select>

                <input type="text" id="filter-search"
                    placeholder="Search repo, file, rule..."
                    oninput="applyFilters()" />

                <label>
                    <input type="checkbox" id="filter-history" onchange="applyFilters()" />
                    History only
                </label>

                <span class="filter-count" id="filter-count"></span>
            </div>

            <div class="table-wrapper">
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Repo</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Rule</th>
                            <th>Match</th>
                        </tr>
                    </thead>
                    <tbody id="findings-body">
                        {table_body}
                    </tbody>
                </table>
            </div>
        </div>

    </div>

    <!-- ── Footer ── -->
    <div class="footer">
        Generated by repo-recon &nbsp;·&nbsp;
        For authorized security research use only
    </div>

    <!-- ── JavaScript for filtering ── -->
    <script>
        // Toggle the MITRE detail panel for a finding row
        function toggleDetail(index) {{
            const detailRow = document.getElementById('detail-' + index);
            const icon = document.getElementById('icon-' + index);
            if (!detailRow) return;
            const isOpen = detailRow.style.display !== 'none';
            detailRow.style.display = isOpen ? 'none' : 'table-row';
            icon.classList.toggle('open', !isOpen);
        }}

        // Store all rows once on page load so we can filter without re-querying
        const allRows = Array.from(document.querySelectorAll('.finding-row'));

        function applyFilters() {{
            // Read current filter values
            const severityFilter  = document.getElementById('filter-severity').value.toLowerCase();
            const categoryFilter  = document.getElementById('filter-category').value.toLowerCase();
            const searchFilter    = document.getElementById('filter-search').value.toLowerCase();
            const historyOnly     = document.getElementById('filter-history').checked;

            let visibleCount = 0;

            allRows.forEach(row => {{
                const severity  = (row.dataset.severity  || '').toLowerCase();
                const category  = (row.dataset.category  || '').toLowerCase();
                const rowText   = row.textContent.toLowerCase();
                const isHistory = row.classList.contains('history-finding');

                // Check each filter condition
                const matchesSeverity  = !severityFilter || severity === severityFilter;
                const matchesCategory  = !categoryFilter || category === categoryFilter;
                const matchesSearch    = !searchFilter   || rowText.includes(searchFilter);
                const matchesHistory   = !historyOnly    || isHistory;

                // Show row only if ALL conditions pass
                if (matchesSeverity && matchesCategory && matchesSearch && matchesHistory) {{
                    row.classList.remove('hidden');
                    visibleCount++;
                }} else {{
                    row.classList.add('hidden');
                }}
            }});

            // Update the count indicator
            const total = allRows.length;
            const countEl = document.getElementById('filter-count');
            countEl.textContent = visibleCount === total
                ? `${{total}} finding(s)`
                : `${{visibleCount}} of ${{total}} finding(s)`;
        }}

        // Run once on load to set the initial count
        applyFilters();
    </script>

</body>
</html>"""

    return html_content
