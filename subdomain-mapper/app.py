"""Streamlit UI wrapper around the scanner pipeline.

    streamlit run app.py
"""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from scanner import main as scanner_main
from viz.build_report import _safe_json, TEMPLATE_PATH

st.set_page_config(
    page_title="Subdomain & Attack Surface Mapper",
    page_icon="🛰️",
    layout="wide",
)

RISK_COLORS = {"high": "#ff3860", "medium": "#ffb020", "low": "#38bdf8"}

st.markdown(
    """
    <style>
      .stApp { background: #070a12; }
      .block-container { padding-top: 2.2rem; max-width: 1500px; }
      h1, h2, h3, p, label, .stMarkdown { color: #dce6f5 !important; }
      [data-testid="stMetricValue"] { font-size: 1.6rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Subdomain & Attack Surface Mapper")
st.caption(
    "Pasivní OSINT recon: certificate transparency logy, DNS brute force a Wayback Machine. "
    "Používejte výhradně na domény, které vlastníte nebo máte písemné svolení testovat."
)

with st.sidebar:
    st.header("Parametry skenu")
    domain = st.text_input("Cílová doména", placeholder="example.com")
    wordlist_size = st.slider(
        "Velikost wordlisty (DNS brute force)", 25, 365, 150, step=25,
        help="Kolik prefixů se zkusí resolvovat. Vyšší číslo = víc nálezů, delší běh.",
    )
    http_timeout = st.slider("HTTP timeout (s)", 1.0, 10.0, 3.0, step=0.5)
    workers = st.slider("Paralelních workerů", 5, 100, 40, step=5)
    use_wayback = st.checkbox("Zahrnout Wayback Machine", value=True)
    st.divider()
    run_scan = st.button("Spustit sken", type="primary", use_container_width=True)
    st.caption(
        "Nástroj neprovádí exploitaci ani skenování zranitelností — "
        "pouze veřejné zdroje a standardní DNS/HTTP dotazy."
    )

if run_scan:
    if not domain.strip():
        st.error("Zadejte cílovou doménu.")
        st.stop()
    try:
        target = scanner_main.validate_domain(domain)
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    progress = st.progress(0.0, text="Sbírám subdomény ze tří zdrojů…")

    # Collection occupies the first 60 % of the bar, enrichment the rest.
    def collect_progress(done: int, total: int) -> None:
        progress.progress(
            0.6 * done / max(total, 1),
            text=f"DNS brute force: {done}/{total} prefixů",
        )

    def enrich_progress(done: int, total: int) -> None:
        progress.progress(
            0.6 + 0.4 * done / max(total, 1),
            text=f"Obohacuji nálezy: {done}/{total} hostů",
        )

    with st.spinner(f"Skenuji {target}…"):
        data = scanner_main.run(
            target,
            wordlist_size=wordlist_size,
            use_wayback=use_wayback,
            http_timeout=http_timeout,
            workers=workers,
            collect_progress=collect_progress,
            enrich_progress=enrich_progress,
        )
    progress.empty()
    st.session_state["data"] = data

data = st.session_state.get("data")

if not data:
    st.info("Zadejte doménu v levém panelu a spusťte sken.")
    st.stop()

summary = data["summary"]
cols = st.columns(6)
cols[0].metric("Hostů celkem", summary["total"])
cols[1].metric("Vysoké riziko", summary["by_risk"]["high"])
cols[2].metric("Střední riziko", summary["by_risk"]["medium"])
cols[3].metric("Živých", summary["alive"])
cols[4].metric("Unikátních IP", summary["unique_ips"])
cols[5].metric("Doba běhu", f"{data['duration_seconds']} s")

tab_graph, tab_table, tab_json = st.tabs(["Graf", "Tabulka", "JSON"])

with tab_graph:
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    html = html.replace("__DATA__", _safe_json(data)).replace("__TARGET__", data["target"])
    components.html(html, height=780, scrolling=False)

with tab_table:
    rows = [
        {
            "hostname": r["hostname"],
            "riziko": r.get("risk", "low"),
            "IP": ", ".join(r["ips"]),
            "status": r.get("status"),
            "title": r.get("title"),
            "server": r.get("server"),
            "zdroj": ", ".join(r.get("sources", [])),
            "sdílí IP s": len(r.get("shared_with", [])),
        }
        for r in data["results"]
    ]
    df = pd.DataFrame(rows)

    risk_filter = st.multiselect(
        "Filtr rizika", ["high", "medium", "low"], default=["high", "medium", "low"]
    )
    view = df[df["riziko"].isin(risk_filter)]

    st.dataframe(
        view.style.map(
            lambda v: f"color: {RISK_COLORS.get(v, '')}; font-weight: 600",
            subset=["riziko"],
        ),
        use_container_width=True,
        height=520,
    )

with tab_json:
    st.json(data, expanded=False)

stamp = datetime.now().strftime("%Y%m%d-%H%M")
report_html = (
    TEMPLATE_PATH.read_text(encoding="utf-8")
    .replace("__DATA__", _safe_json(data))
    .replace("__TARGET__", data["target"])
)

dl1, dl2 = st.columns(2)
dl1.download_button(
    "Stáhnout results.json",
    json.dumps(data, indent=2, ensure_ascii=False),
    file_name=f"{stamp}-{data['target']}-results.json",
    mime="application/json",
    use_container_width=True,
)
dl2.download_button(
    "Stáhnout report.html",
    report_html,
    file_name=f"{stamp}-{data['target']}-report.html",
    mime="text/html",
    use_container_width=True,
)
