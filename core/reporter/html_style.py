"""Static CSS block for the HTML report.

Kept in its own module so html_export.py stays short and testable.
"""

HTML_STYLE = """
:root {
    --bg: #0a0a0a;
    --bg-elevated: #111;
    --bg-soft: #171717;
    --line: #2c2c2c;
    --line-strong: #3a3a3a;
    --text: #e8e8e8;
    --muted: #9a9a9a;
    --accent: #ff4d4d;
    --accent-soft: #ff9b7a;
    --link: #78b8ff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Courier New', monospace;
    background:
        radial-gradient(circle at top, rgba(255, 77, 77, 0.15), transparent 35%),
        linear-gradient(180deg, #111 0%, var(--bg) 24%);
    color: var(--text);
    padding: 2rem;
    line-height: 1.5;
}
h1 { color: var(--accent); text-align: center; letter-spacing: 0.12em; margin-bottom: 0.5rem; }
h2 {
    color: var(--accent-soft);
    margin: 2rem 0 1rem;
    border-bottom: 1px solid var(--line-strong);
    padding-bottom: 0.5rem;
}
h3 { color: #ffb5a0; margin-bottom: 0.75rem; }
.meta { text-align: center; color: var(--muted); margin-bottom: 2rem; }
.summary {
    background: rgba(17, 17, 17, 0.85);
    border: 1px solid var(--line-strong);
    border-radius: 12px;
    padding: 1.5rem;
    margin: 1rem 0;
    backdrop-filter: blur(8px);
}
.summary span { color: var(--accent); font-weight: bold; }
.grid { display: grid; gap: 1rem; }
.grid-2 { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
.grid-3 { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.card {
    background: rgba(17, 17, 17, 0.88);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 1rem;
    margin: 0.75rem 0;
}
.card-full { grid-column: 1 / -1; }
.metric-card { display: flex; flex-direction: column; justify-content: center; min-height: 160px; }
.metric-label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.9rem; }
.metric-value { color: var(--accent); font-size: 2.6rem; font-weight: bold; margin-top: 0.5rem; }
.badge {
    display: inline-block;
    padding: 0.35rem 0.6rem;
    margin: 0.25rem;
    border-radius: 999px;
    background: var(--bg-soft);
    border: 1px solid var(--line);
    color: var(--text);
}
.brief-headline {
    padding: 0.9rem 1rem;
    border: 1px solid var(--line-strong);
    border-radius: 10px;
    background: rgba(17, 17, 17, 0.88);
    color: var(--text);
    margin-bottom: 1rem;
    font-weight: bold;
}
.brief-metrics {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}
.metric-chip {
    min-width: 180px;
    padding: 0.75rem 0.9rem;
    border-radius: 10px;
    border: 1px solid var(--line-strong);
    background: rgba(17, 17, 17, 0.88);
}
.metric-chip span {
    display: block;
    color: var(--muted);
    font-size: 0.82rem;
    margin-bottom: 0.2rem;
}
.metric-chip strong {
    color: var(--accent);
    text-transform: capitalize;
}
.risk-list {
    list-style: none;
    padding: 0;
    margin: 0;
}
.risk-item {
    border-left: 3px solid var(--line-strong);
    padding: 0.5rem 0.75rem;
    margin: 0.5rem 0;
    background: rgba(255, 255, 255, 0.02);
}
.risk-item strong {
    display: block;
    margin-bottom: 0.2rem;
}
.risk-high { border-left-color: #ff4d4d; }
.risk-medium { border-left-color: #ffb36b; }
.risk-low { border-left-color: #6cb7ff; }
.muted { color: var(--muted); }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; background: rgba(17, 17, 17, 0.86); }
th {
    background: #1a1a1a;
    color: var(--accent-soft);
    padding: 0.75rem;
    text-align: left;
    border: 1px solid var(--line-strong);
}
td { padding: 0.75rem; border: 1px solid var(--line); vertical-align: top; }
tr:hover { background: #141414; }
a { color: var(--link); }
ul { list-style: none; padding-left: 0; }
li { margin: 0.45rem 0; }
li strong { color: #ffb5a0; }
@media (max-width: 700px) {
    body { padding: 1rem; }
    .metric-value { font-size: 2rem; }
}
"""
