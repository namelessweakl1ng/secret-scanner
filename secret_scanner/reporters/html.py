"""HTML reporter: professional dashboard with charts and statistics."""

from __future__ import annotations

import json
from collections import Counter
from html import escape

from .base import Reporter

# Chart.js CDN URL for the dashboard charts.
_CHARTJS_CDN = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"


class HTMLReporter(Reporter):
    """Render a self-contained HTML dashboard."""

    def render(self, result) -> str:  # noqa: ANN001
        counts = result.severity_counts()
        risk = result.risk_score()
        risk_color = "#dc2626" if risk >= 50 else "#eab308" if risk >= 25 else "#16a34a"

        sorted_findings = sorted(
            result.findings,
            key=lambda f: (-f.severity.value, -f.confidence),
        )

        # Aggregate stats.
        providers = Counter(f.provider for f in result.findings).most_common(10)
        files = Counter(f.file_path for f in result.findings).most_common(10)
        rules = Counter(f.rule_name for f in result.findings).most_common(10)

        rows_html: list[str] = []
        for i, f in enumerate(sorted_findings, start=1):
            sev_badge = self._sev_badge(f.severity.label)
            conf_color = self._conf_color(f.confidence)
            rows_html.append(f"""
<tr>
  <td class="num">{i}</td>
  <td>{sev_badge}</td>
  <td>{escape(f.rule_name)}</td>
  <td class="filepath">{escape(f.file_path)}<span class="line">:{f.line_number}</span></td>
  <td class="num">{f.confidence}%</td>
  <td class="conf-bar"><div class="conf-fill" style="width:{f.confidence}%;background:{conf_color}"></div></td>
  <td class="masked">{escape(f.masked_value)}</td>
  <td>{escape(f.provider)}</td>
</tr>""")

        "\n".join(
            f"<tr><td>{escape(p)}</td><td class='num'>{c}</td></tr>" for p, c in providers
        ) or "<tr><td colspan='2'>N/A</td></tr>"
        file_rows = (
            "\n".join(
                f"<tr><td class='filepath'>{escape(fp)}</td><td class='num'>{c}</td></tr>"
                for fp, c in files
            )
            or "<tr><td colspan='2'>N/A</td></tr>"
        )
        rule_rows = (
            "\n".join(f"<tr><td>{escape(r)}</td><td class='num'>{c}</td></tr>" for r, c in rules)
            or "<tr><td colspan='2'>N/A</td></tr>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secret Scanner Report — {escape(result.target)}</title>
<script src="{_CHARTJS_CDN}"></script>
<style>
  :root {{
    --bg: #0f172a;
    --panel: #1e293b;
    --panel-2: #273449;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --border: #334155;
    --critical: #dc2626;
    --high: #ef4444;
    --medium: #eab308;
    --low: #06b6d4;
    --info: #64748b;
    --accent: #06b6d4;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }}
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 48px;
  }}
  .header h1 {{
    margin: 0 0 8px 0;
    font-size: 28px;
    font-weight: 700;
  }}
  .header .target {{
    color: var(--muted);
    font-family: 'SF Mono', Menlo, monospace;
    font-size: 13px;
  }}
  .container {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 32px 48px;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }}
  .stat .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat .value {{ font-size: 32px; font-weight: 700; margin-top: 4px; }}
  .stat.critical .value {{ color: var(--critical); }}
  .stat.high .value {{ color: var(--high); }}
  .stat.medium .value {{ color: var(--medium); }}
  .stat.low .value {{ color: var(--low); }}
  .risk-gauge {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 32px;
  }}
  .risk-gauge .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .risk-bar {{
    height: 24px;
    background: var(--panel-2);
    border-radius: 12px;
    overflow: hidden;
    margin-top: 12px;
    position: relative;
  }}
  .risk-fill {{
    height: 100%;
    background: {risk_color};
    border-radius: 12px;
    transition: width 0.5s ease;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding-right: 12px;
    color: white;
    font-weight: 700;
    font-size: 12px;
  }}
  .charts {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-bottom: 32px;
  }}
  .chart-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }}
  .chart-card h3 {{ margin: 0 0 16px 0; font-size: 16px; font-weight: 600; }}
  .chart-container {{ position: relative; height: 240px; }}
  .table-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 32px;
    overflow-x: auto;
  }}
  .table-card h3 {{ margin: 0 0 16px 0; font-size: 16px; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.filepath {{ font-family: 'SF Mono', Menlo, monospace; font-size: 12px; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  td.filepath .line {{ color: var(--muted); }}
  td.masked {{ font-family: 'SF Mono', Menlo, monospace; font-size: 12px; color: var(--accent); }}
  .conf-bar {{ min-width: 80px; }}
  .conf-fill {{ height: 6px; border-radius: 3px; }}
  .sev-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .sev-badge.Critical {{ background: var(--critical); color: white; }}
  .sev-badge.High {{ background: var(--high); color: white; }}
  .sev-badge.Medium {{ background: var(--medium); color: #1f2937; }}
  .sev-badge.Low {{ background: var(--low); color: white; }}
  .sev-badge.Info {{ background: var(--info); color: white; }}
  .footer {{ text-align: center; color: var(--muted); padding: 24px 0; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Secret Scanner Report</h1>
  <div class="target">{escape(result.target)} · {result.scan_type} · {result.started_at.isoformat() if result.started_at else ''}</div>
</div>

<div class="container">
  <div class="grid">
    <div class="stat"><div class="label">Files Scanned</div><div class="value">{result.files_scanned}</div></div>
    <div class="stat"><div class="label">Files Skipped</div><div class="value">{result.files_skipped}</div></div>
    <div class="stat"><div class="label">Total Findings</div><div class="value">{result.finding_count}</div></div>
    <div class="stat"><div class="label">Unique Secrets</div><div class="value">{result.unique_secrets}</div></div>
    <div class="stat critical"><div class="label">Critical</div><div class="value">{counts['Critical']}</div></div>
    <div class="stat high"><div class="label">High</div><div class="value">{counts['High']}</div></div>
    <div class="stat medium"><div class="label">Medium</div><div class="value">{counts['Medium']}</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value">{counts['Low']}</div></div>
  </div>

  <div class="risk-gauge">
    <div class="label">Repository Risk Score</div>
    <div class="risk-bar"><div class="risk-fill" style="width:{risk}%">{risk}/100</div></div>
  </div>

  <div class="charts">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <div class="chart-container"><canvas id="sevChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Top Providers</h3>
      <div class="chart-container"><canvas id="provChart"></canvas></div>
    </div>
  </div>

  <div class="table-card">
    <h3>Findings ({len(sorted_findings)} total)</h3>
    <table>
      <thead>
        <tr><th>#</th><th>Severity</th><th>Type</th><th>File</th><th>Confidence</th><th></th><th>Value (masked)</th><th>Provider</th></tr>
      </thead>
      <tbody>
        {''.join(rows_html) if rows_html else '<tr><td colspan="8" style="text-align:center;color:#16a34a;padding:32px;">✅ No secrets found</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="charts">
    <div class="table-card">
      <h3>Top Affected Files</h3>
      <table><thead><tr><th>File</th><th>Findings</th></tr></thead><tbody>{file_rows}</tbody></table>
    </div>
    <div class="table-card">
      <h3>Top Detection Rules</h3>
      <table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>{rule_rows}</tbody></table>
    </div>
  </div>
</div>

<div class="footer">Generated by Secret Scanner v{result.scanner_version}</div>

<script>
const ctx1 = document.getElementById('sevChart');
const ctx2 = document.getElementById('provChart');
const sevData = {{
  labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
  datasets: [{{
    label: 'Findings',
    data: [{counts['Critical']}, {counts['High']}, {counts['Medium']}, {counts['Low']}, {counts['Info']}],
    backgroundColor: ['#dc2626', '#ef4444', '#eab308', '#06b6d4', '#64748b'],
    borderWidth: 0,
  }}],
}};
const provLabels = {json.dumps([p for p, _ in providers])};
const provData = {json.dumps([c for _, c in providers])};
new Chart(ctx1, {{type: 'doughnut', data: sevData, options: {{plugins: {{legend: {{position: 'right', labels: {{color: '#e2e8f0'}}}}}}}}}});
new Chart(ctx2, {{
  type: 'bar',
  data: {{labels: provLabels, datasets: [{{label: 'Findings', data: provData, backgroundColor: '#06b6d4', borderWidth: 0}}]}},
  options: {{indexAxis: 'y', plugins: {{legend: {{display: false}}}}, scales: {{x: {{ticks: {{color: '#94a3b8'}}, grid: {{color: '#334155'}}}}, y: {{ticks: {{color: '#94a3b8'}}, grid: {{display: false}}}}}}}},
}});
</script>
</body>
</html>"""

    @staticmethod
    def _sev_badge(label: str) -> str:
        return f'<span class="sev-badge {label}">{label}</span>'

    @staticmethod
    def _conf_color(conf: int) -> str:
        if conf >= 80:
            return "#dc2626"
        if conf >= 60:
            return "#ef4444"
        if conf >= 40:
            return "#eab308"
        return "#06b6d4"


__all__ = ["HTMLReporter"]
