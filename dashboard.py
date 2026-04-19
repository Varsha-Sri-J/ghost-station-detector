"""
dashboard.py  —  Ghost Station Detector · GhostWire Security Platform

Run:
    streamlit run dashboard.py

Requires:
    python ca_setup.py      (once)
    python station_sim.py   (keep running in a separate terminal)
"""

import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go
import statistics
import os
import time
from ev_sentinel import run_evaluation

st.set_page_config(
    page_title="Ghost Station Detector",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0b0d12;
    color: #cdd5e0;
}
.stApp { background-color: #0b0d12; }

/* ── HEADER ── */
.hdr {
    padding: 1.4rem 2.4rem 1.2rem;
    margin-bottom: 0;
    border-bottom: 2px solid #1e3a28;
    display: flex; align-items: center; justify-content: space-between;
    background: #080a0e;
}
.hdr-logo {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.8rem; font-weight: 700;
    color: #3ecf80; letter-spacing: 0.06em;
}
.hdr-brand {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.9rem; font-weight: 500;
    color: #4a7a5a; letter-spacing: 0.1em;
    text-transform: uppercase; margin-top: 0.15rem;
}
.hdr-tags {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.85rem; font-weight: 600;
    color: #3a6a4a; letter-spacing: 0.06em;
    text-align: right; text-transform: uppercase; line-height: 2;
}

/* ── TABS ── */
div[data-testid="stTabs"] button {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 1rem !important; font-weight: 600 !important;
    letter-spacing: 0.1em !important; color: #4a6a5a !important;
    border-bottom: 2px solid transparent !important;
    padding: 0.65rem 1.8rem !important; text-transform: uppercase !important;
    transition: color 0.15s !important;
}
div[data-testid="stTabs"] button[aria-selected="true"] {
    color: #3ecf80 !important;
    border-bottom: 2px solid #3ecf80 !important;
}
div[data-testid="stTabs"] button:hover {
    color: #6adfa0 !important;
}

/* ── RADIO ── */
div[data-testid="stRadio"] > label { display: none; }
div[data-testid="stRadio"] div[role="radiogroup"] { gap: 0 !important; }
div[data-testid="stRadio"] label[data-baseweb="radio"] {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 1.05rem !important; font-weight: 600 !important;
    color: #6a9a7a !important; letter-spacing: 0.06em !important;
    background: #0e1410 !important; border: 1px solid #1e3228 !important;
    border-radius: 5px !important; padding: 0.75rem 1.2rem !important;
    margin-bottom: 7px !important; width: 100% !important;
    transition: border-color 0.2s, color 0.2s, background 0.2s !important;
    text-transform: uppercase !important;
}
div[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) {
    border-color: #3ecf80 !important; color: #3ecf80 !important;
    background: #071610 !important; border-width: 2px !important;
}

/* ── BASE CARDS ── */
.card {
    background: #0e1410; border: 1px solid #1e3228;
    border-radius: 6px; padding: 1.3rem 1.5rem;
}
.card-dim {
    background: #0b100c; border: 1px solid #162420;
    border-radius: 6px; padding: 1.1rem 1.3rem;
}

/* ── TYPOGRAPHY ── */
.sec-heading {
    font-family: 'Rajdhani', sans-serif; font-size: 1.2rem; font-weight: 700;
    color: #cdd5e0; text-transform: uppercase; letter-spacing: 0.15em;
    margin-bottom: 1rem; margin-top: 0;
}
.mlabel {
    font-family: 'Rajdhani', sans-serif; font-size: 0.82rem; font-weight: 600;
    color: #5a8a6a; text-transform: uppercase; letter-spacing: 0.12em;
    margin-bottom: 0.4rem;
}
.mdetail {
    font-family: 'Share Tech Mono', monospace; font-size: 0.84rem;
    color: #6a9a7a; margin-top: 0.4rem; line-height: 1.6;
}

/* ── SECTION DIVIDER ── */
.sec-div {
    border-top: 1px solid #1e3228; margin: 2rem 0 1.3rem;
    display: flex; align-items: center; gap: 14px;
}
.sec-label {
    font-family: 'Rajdhani', sans-serif; font-size: 0.95rem; font-weight: 700;
    color: #4a7a5a; text-transform: uppercase; letter-spacing: 0.15em;
    white-space: nowrap; padding-top: 2px;
}

/* ── TRUST SCORE ── */
.trust-wrap { text-align: center; padding: 1.8rem 0 1.2rem; }
.trust-score {
    font-family: 'Share Tech Mono', monospace;
    font-size: 7.5rem; font-weight: 400; line-height: 1;
}
.trust-label {
    font-family: 'Rajdhani', sans-serif; font-size: 1rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.2em; margin-top: 0.5rem;
    color: #5a8a6a;
}
.trust-drop {
    font-family: 'Share Tech Mono', monospace; font-size: 1.5rem;
    margin-top: 0.7rem; letter-spacing: 0.04em;
}
.trust-drop-label {
    font-family: 'Rajdhani', sans-serif; font-size: 0.9rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.15em; margin-top: 0.3rem;
}

/* ── STATUS BANNER ── */
.banner {
    width: 100%; padding: 1.5rem 2rem; border-radius: 6px;
    margin: 1rem 0; display: flex; align-items: center; gap: 1.4rem;
    border-width: 2px; border-style: solid;
}
.banner-text {
    font-family: 'Rajdhani', sans-serif; font-size: 1.7rem;
    font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
}
.banner-sub {
    font-family: 'Share Tech Mono', monospace; font-size: 0.85rem;
    margin-top: 0.3rem; opacity: 0.85; line-height: 1.5;
}

/* ── PHASE PILLS ── */
.phase-row {
    display: flex; gap: 6px; align-items: center;
    margin: 0.9rem 0; flex-wrap: wrap;
}
.ppill {
    font-family: 'Rajdhani', sans-serif; font-size: 0.72rem; font-weight: 600;
    padding: 3px 11px; border-radius: 3px;
    border: 1px solid #1e3228; color: #3a5a4a;
    background: #0b100c; letter-spacing: 0.08em; text-transform: uppercase;
}
.ppill.pass { border-color: #2a7a4a; color: #3ecf80; background: #071610; border-width: 2px; }
.ppill.warn { border-color: #8a6800; color: #f5b942; background: #130f00; border-width: 2px; }
.ppill.fail { border-color: #8a2222; color: #f56060; background: #130808; border-width: 2px; }

/* ── STATUS ROWS ── */
.srow {
    display: flex; align-items: center; gap: 14px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.88rem;
    padding: 0.6rem 1.1rem; border-radius: 5px;
    background: #0e1410; border: 1px solid #1e3228; margin: 0.38rem 0;
}
.srow-label {
    font-family: 'Rajdhani', sans-serif; font-weight: 600;
    font-size: 0.92rem; color: #cdd5e0; min-width: 130px;
    text-transform: uppercase; letter-spacing: 0.06em;
}
.srow-val { color: #6a9a7a; }
.g { color: #3ecf80; } .r { color: #f56060; } .a { color: #f5b942; }

/* ── CONNECTION FLOW ── */
.cf-step {
    font-family: 'Share Tech Mono', monospace; font-size: 0.92rem;
    padding: 0.55rem 1rem; border-left: 3px solid #1e3228;
    margin-bottom: 0.38rem; color: #3a5a4a; letter-spacing: 0.04em;
}
.cf-step.done   { border-left-color: #3ecf80; color: #3ecf80; }
.cf-step.active { border-left-color: #3ecf80; color: #8af0c0; animation: blink 0.9s ease infinite; }
.cf-step.fail   { border-left-color: #f56060; color: #f56060; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }

/* ── THREAT MODEL ── */
.tcard {
    background: #0d1020; border: 1px solid #1e2240;
    border-radius: 6px; padding: 1rem 1.3rem; margin-bottom: 0.6rem;
}
.tkey {
    font-family: 'Rajdhani', sans-serif; color: #8070e0;
    font-size: 0.85rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.12em; min-width: 120px; flex-shrink: 0; padding-top: 2px;
}
.tval { color: #9aaac8; line-height: 1.65; font-size: 0.9rem; }

/* ── BREACH PANEL ── */
.bpanel {
    background: #130a0a; border: 2px solid #4a1a1a;
    border-radius: 6px; padding: 1.3rem 1.6rem; margin-bottom: 1rem;
}
.btitle {
    font-family: 'Rajdhani', sans-serif; font-size: 0.95rem; font-weight: 700;
    color: #f56060; text-transform: uppercase; letter-spacing: 0.1em;
    margin-bottom: 0.85rem;
}
.bline { font-family: 'Share Tech Mono', monospace; font-size: 0.85rem; line-height: 2.1; }
.bhl   { color: #f56060; }
.bdim  { color: #6a3a3a; }

/* ── LOG BOX ── */
.lbox {
    font-family: 'Share Tech Mono', monospace; font-size: 0.82rem;
    background: #080a0e; border: 1px solid #1a2a20; border-radius: 4px;
    padding: 1rem; max-height: 250px; overflow-y: auto; line-height: 2;
}
.lp { color: #3ecf80; } .lf { color: #f56060; }
.lw { color: #f5b942; } .li { color: #6090f0; } .ln { color: #4a6a5a; }

/* ── BUTTON ── */
.stButton > button {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 1.05rem !important; font-weight: 700 !important;
    letter-spacing: 0.1em !important; border-radius: 5px !important;
    border: 2px solid #2a7a4a !important;
    background: #071610 !important; color: #3ecf80 !important;
    text-transform: uppercase !important; transition: all 0.15s !important;
    padding: 0.6rem 1.4rem !important;
}
.stButton > button:hover {
    background: #0a2a18 !important; border-color: #3ecf80 !important;
}

/* ── COVERAGE ITEMS ── */
.citem {
    display: flex; gap: 14px; align-items: flex-start;
    font-family: 'Share Tech Mono', monospace; font-size: 0.85rem;
    padding: 0.6rem 1.1rem; border-radius: 5px;
    background: #0e1410; border: 1px solid #1e3228; margin: 0.32rem 0;
}
.ckey {
    font-family: 'Rajdhani', sans-serif; font-weight: 700;
    color: #3ecf80; min-width: 110px; font-size: 0.8rem;
    flex-shrink: 0; padding-top: 2px; text-transform: uppercase;
    letter-spacing: 0.08em;
}
.cval { color: #6a9a7a; line-height: 1.5; }

/* ── SESSION INTEGRITY BADGE ── */
.int-badge {
    width: 100%; padding: 1rem 1.5rem; border-radius: 5px;
    margin-bottom: 0.9rem; display: flex;
    align-items: center; justify-content: space-between;
    border-width: 2px; border-style: solid;
}
.int-label {
    font-family: 'Rajdhani', sans-serif; font-size: 1.15rem;
    font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
}
.int-count {
    font-family: 'Rajdhani', sans-serif; font-size: 0.85rem;
    font-weight: 500; opacity: 0.8;
}

/* ── MESSAGE COUNT CARDS ── */
.mini-count-card {
    background: #0e1410; border: 1px solid #1e3228;
    border-radius: 5px; padding: 1rem 1.1rem; text-align: center;
}
.mini-count-val {
    font-family: 'Share Tech Mono', monospace; font-size: 2.1rem; line-height: 1;
}
.mini-count-label {
    font-family: 'Rajdhani', sans-serif; font-size: 0.85rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.1em; color: #5a8a6a; margin-top: 0.3rem;
}

/* ── REACTION BLOCK ── */
.reaction-block {
    margin-top: 1rem; padding: 1.1rem 1.5rem;
    border-radius: 6px; border-width: 2px; border-style: solid;
}
.reaction-title {
    font-family: 'Rajdhani', sans-serif; font-size: 1.1rem;
    font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
}
.reaction-detail {
    font-family: 'Share Tech Mono', monospace; font-size: 0.82rem;
    margin-top: 0.4rem; line-height: 1.65;
}
</style>
""", unsafe_allow_html=True)

# ── HEADER ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hdr">
  <div>
    <div class="hdr-logo">Ghost Station Detector</div>
    <div class="hdr-brand">GhostWire Security Platform</div>
  </div>
  <div class="hdr-tags">
    Identity Verification · Behaviour Monitoring · Trust Scoring
  </div>
</div>
""", unsafe_allow_html=True)

# ── TABS ──────────────────────────────────────────────────────────────────────
tab_before, tab_live, tab_threat = st.tabs([
    "WITHOUT PROTECTION",
    "LIVE SECURITY CHECK",
    "THREAT MODEL",
])


# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — WITHOUT PROTECTION
# ═════════════════════════════════════════════════════════════════════════════
with tab_before:
    st.markdown("<div style='height:0.7rem'></div>", unsafe_allow_html=True)
    b1, b2 = st.columns([1, 1], gap="large")

    with b1:
        st.markdown('<div class="sec-heading">What Happens Without Protection</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="tcard">
          <div style="display:flex;gap:14px;margin-bottom:0.6rem">
            <span class="tkey">Station</span>
            <span class="tval">A fake charging station broadcasts a spoofed identity on the same communication channel as a real station.</span>
          </div>
          <div style="display:flex;gap:14px;margin-bottom:0.6rem">
            <span class="tkey">Method</span>
            <span class="tval">The vehicle connects without verifying the station's certificate. No trust check is performed.</span>
          </div>
          <div style="display:flex;gap:14px;margin-bottom:0.6rem">
            <span class="tkey">Result</span>
            <span class="tval">The vehicle immediately sends its billing identity and session credentials to the attacker.</span>
          </div>
          <div style="display:flex;gap:14px">
            <span class="tkey">Impact</span>
            <span class="tval">Billing fraud · identity theft · attacker controls charging behaviour remotely</span>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:0.7rem'></div>", unsafe_allow_html=True)
        run_attack = st.button("Simulate Attack — No Protection Active", use_container_width=True)

    with b2:
        if run_attack:
            lines = [
                ("bdim", "[FakeStation] Broadcasting as EVSE-LEGIT-001 — spoofed identity"),
                ("bdim", "[FakeStation] Vehicle connected — no certificate validation performed"),
                ("bdim", "[FakeStation] Received discovery request from vehicle"),
                ("bdim", "[FakeStation] Unverified certificate accepted by vehicle firmware"),
                ("bhl",  "[FakeStation] CONTRACT CERTIFICATE RECEIVED"),
                ("bhl",  "[FakeStation] Contract ID   :  EV-CONTRACT-VIN-001"),
                ("bhl",  "[FakeStation] Vehicle VIN   :  WBA-DEMO-1234567890"),
                ("bhl",  "[FakeStation] Billing ID    :  CC-VISA-****-7823"),
                ("bdim", "[FakeStation] Injecting price:  $9.99/kWh  (real price: $0.25)"),
                ("bdim", "[FakeStation] Modifying voltage target:  320V  (requested: 400V)"),
                ("bhl",  "[FakeStation] DATA EXFILTRATION COMPLETE — VEHICLE COMPROMISED"),
            ]
            ph = b2.empty()
            rendered = ['<div class="bpanel"><div class="btitle">Fake Station Console — Live Attack Log</div>']
            for cls, text in lines:
                rendered.append(f'<div class="bline {cls}">{text}</div>')
                ph.markdown("".join(rendered) + "</div>", unsafe_allow_html=True)
                time.sleep(0.30)
            st.markdown("""
            <div class="srow" style="border-color:#8a2222;background:#130808;margin-top:0.7rem">
              <span class="r" style="font-size:1rem">—</span>
              <span style="color:#f56060;font-size:0.92rem;font-family:'Rajdhani',sans-serif;font-weight:600;letter-spacing:0.04em">
                Billing credentials stolen · Session compromised · No protection active
              </span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="height:300px;display:flex;align-items:center;justify-content:center;
                        border:2px solid #4a1a1a;border-radius:6px;background:#0e0808;">
              <div style="text-align:center">
                <div style="font-family:'Rajdhani',sans-serif;font-size:1.2rem;font-weight:700;
                            color:#7a2a2a;letter-spacing:0.15em;text-transform:uppercase">
                  No attack running
                </div>
                <div style="font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:500;
                            color:#4a2020;margin-top:0.5rem;letter-spacing:0.05em">
                  Click the button to simulate what happens without GhostWire
                </div>
              </div>
            </div>""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — LIVE SECURITY CHECK
# ═════════════════════════════════════════════════════════════════════════════
with tab_live:
    st.markdown("<div style='height:0.7rem'></div>", unsafe_allow_html=True)
    left, right = st.columns([1, 2.2], gap="large")

    # ── Left panel ─────────────────────────────────────────────────────────
    with left:
        st.markdown('<div class="sec-heading">Select Station Type</div>', unsafe_allow_html=True)

        mode = st.radio(
            "Station mode",
            options=["legit", "suspicious", "rogue"],
            format_func=lambda m: {
                "legit":      "Legitimate Station",
                "suspicious": "Suspicious Station",
                "rogue":      "Rogue Station (Fake)",
            }[m],
            label_visibility="collapsed",
        )

        mode_info = {
            "legit":      {
                "cert":  "Certificate signed by trusted authority",
                "rtt":   "Response time normal (~15 ms)",
                "volt":  "Power delivery stable (±1V)",
            },
            "suspicious": {
                "cert":  "Certificate signed by trusted authority",
                "rtt":   "Response time elevated (~90 ms)",
                "volt":  "Power delivery unstable (±12V)",
            },
            "rogue":      {
                "cert":  "Certificate is self-signed — not trusted",
                "rtt":   "Response time anomalous (~160 ms)",
                "volt":  "Power delivery erratic (±30V)",
            },
        }[mode]

        st.markdown(f"""
        <div class="card-dim" style="margin-top:0.6rem;margin-bottom:1rem">
          <div class="mlabel">What to expect</div>
          <div style="margin-top:0.5rem;line-height:2.2">
            <div style="display:flex;gap:8px">
              <span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:0.82rem;
                           color:#3a6a4a;min-width:70px;text-transform:uppercase">Cert</span>
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.82rem;color:#8aaa9a">{mode_info['cert']}</span>
            </div>
            <div style="display:flex;gap:8px">
              <span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:0.82rem;
                           color:#3a6a4a;min-width:70px;text-transform:uppercase">Timing</span>
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.82rem;color:#8aaa9a">{mode_info['rtt']}</span>
            </div>
            <div style="display:flex;gap:8px">
              <span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:0.82rem;
                           color:#3a6a4a;min-width:70px;text-transform:uppercase">Power</span>
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.82rem;color:#8aaa9a">{mode_info['volt']}</span>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        run_clicked = st.button("Run Security Check", use_container_width=True)
        if run_clicked:
            with open("station_mode.txt", "w") as f:
                f.write(mode)

        st.markdown("<div style='height:1.2rem'></div>", unsafe_allow_html=True)
        st.markdown('<div class="sec-heading" style="font-size:1rem">Security Features</div>', unsafe_allow_html=True)
        for key, val in [
            ("Identity Check",    "Both station and vehicle verify each other"),
            ("Key Protection",    "Private keys are sealed and never exposed"),
            ("Attack Detection",  "Response timing and power delivery analysed"),
            ("Privacy Guard",     "Billing ID withheld until station is verified"),
        ]:
            st.markdown(f"""
            <div class="citem"><span class="ckey">{key}</span><span class="cval">{val}</span></div>
            """, unsafe_allow_html=True)

    # ── Right panel ────────────────────────────────────────────────────────
    with right:
        if not run_clicked:
            st.markdown("""
            <div style="height:320px;display:flex;align-items:center;justify-content:center;
                        border:2px solid #1e3228;border-radius:6px;background:#0b100c;">
              <div style="text-align:center">
                <div style="font-family:'Rajdhani',sans-serif;font-size:1.2rem;font-weight:700;
                            color:#2a5a3a;letter-spacing:0.15em;text-transform:uppercase">
                  Ready to Scan
                </div>
                <div style="font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:500;
                            color:#1a3a28;margin-top:0.5rem">
                  Select a station type and click Run Security Check
                </div>
              </div>
            </div>""", unsafe_allow_html=True)

        else:
            if not os.path.exists("certs/root_ca.pem"):
                st.error("certs/root_ca.pem not found — run python ca_setup.py first.")
                st.stop()

            # ── SECTION 1: Connection flow ──────────────────────────────────
            st.markdown('<div class="sec-div"><span class="sec-label">Verification Steps</span><span style="flex:1;border-top:1px solid #1e3228;margin-left:12px"></span></div>', unsafe_allow_html=True)

            flow_steps = [
                "Connecting to charging station",
                "Verifying station identity",
                "Confirming vehicle identity",
                "Measuring communication timing",
                "Analysing power delivery",
                "Computing trust score",
            ]
            cf_placeholder = st.empty()

            def render_flow(completed, active_idx=None, failed_idx=None):
                html = '<div style="padding:0.2rem 0">'
                for i, step in enumerate(flow_steps):
                    if failed_idx is not None and i == failed_idx:
                        cls, prefix = "fail", "FAIL"
                    elif i < completed:
                        cls, prefix = "done", "DONE"
                    elif i == active_idx:
                        cls, prefix = "active", "..."
                    else:
                        cls, prefix = "", "WAIT"
                    html += f'<div class="cf-step {cls}">{prefix}  {step}</div>'
                html += "</div>"
                cf_placeholder.markdown(html, unsafe_allow_html=True)

            for i in range(len(flow_steps)):
                render_flow(i, active_idx=i)
                time.sleep(0.28)

            result = run_evaluation()

            if result.get("error"):
                render_flow(0, failed_idx=0)
                st.error(f"Connection failed — {result['error']}")
                st.markdown(
                    "<div style='font-family:Rajdhani,sans-serif;font-size:0.9rem;font-weight:500;color:#7a9a8a'>"
                    "Make sure station_sim.py is running in a separate terminal.</div>",
                    unsafe_allow_html=True
                )
                st.stop()

            cert_ok = result.get("cert_score", 0) > 0
            render_flow(1, failed_idx=1) if not cert_ok else render_flow(len(flow_steps))

            score     = result["trust_score"]
            decision  = result["decision"]
            color     = {"ALLOWED": "#3ecf80", "SAFE MODE": "#f5b942", "BLOCKED": "#f56060"}[decision]
            initial_t = result.get("initial_trust_score", score)
            current_t = result.get("current_trust_score", score)
            penalty   = result.get("signal_penalty", 0)

            # ── SECTION 2: Trust score ──────────────────────────────────────
            st.markdown('<div class="sec-div"><span class="sec-label">Trust Score</span><span style="flex:1;border-top:1px solid #1e3228;margin-left:12px"></span></div>', unsafe_allow_html=True)

            ts_col, dec_col = st.columns([1, 1.6], gap="medium")

            with ts_col:
                if initial_t != current_t:
                    drop_c = "#f56060" if penalty >= 30 else "#f5b942"
                    st.markdown(f"""
                    <div class="trust-wrap">
                      <div class="trust-score" style="color:{drop_c}">{current_t}</div>
                      <div class="trust-label" style="color:{drop_c}">Trust reduced during session</div>
                      <div class="trust-drop" style="color:{drop_c}">
                        <span style="color:#6a9a7a">{initial_t}</span>
                        <span style="margin:0 12px;color:#8aaa9a">to</span>
                        <span>{current_t}</span>
                        <span style="font-size:0.95rem;margin-left:10px;opacity:0.85"> minus {penalty}</span>
                      </div>
                      <div class="trust-drop-label" style="color:{drop_c}">Suspicious activity detected</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="trust-wrap">
                      <div class="trust-score" style="color:{color}">{score}</div>
                      <div class="trust-label" style="color:{color}">Trust score</div>
                      <div style="font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:500;
                                  color:#5a8a6a;margin-top:0.5rem;letter-spacing:0.06em">
                        No anomalies detected
                      </div>
                    </div>
                    """, unsafe_allow_html=True)

                # Phase breadcrumb
                phase_order    = ["CERT", "MUTUAL AUTH", "RTT", "PROBE", "DECISION", "RUNTIME"]
                phase_outcomes = result.get("phase_outcomes", {})
                ph = '<div class="phase-row">'
                for p in phase_order:
                    oc  = phase_outcomes.get(p, "pending")
                    css = {"pass": "ppill pass", "warn": "ppill warn", "fail": "ppill fail"}.get(oc, "ppill")
                    ph += f'<div class="{css}">{p}</div>'
                    if p != phase_order[-1]:
                        ph += '<span style="color:#2a4a3a;font-size:0.72rem;margin:0 1px">›</span>'
                ph += "</div>"
                st.markdown(ph, unsafe_allow_html=True)

            with dec_col:
                # Decision banner — no icons, just clear text
                banner_cfg = {
                    "ALLOWED":   ("#3ecf80", "#071610", "#2a7a4a", "CONNECTION ALLOWED"),
                    "SAFE MODE": ("#f5b942", "#130f00", "#8a6800", "RESTRICTED MODE"),
                    "BLOCKED":   ("#f56060", "#130808", "#8a2222", "CONNECTION BLOCKED"),
                }
                bc, bbg, bbdr, blabel = banner_cfg[decision]
                st.markdown(f"""
                <div class="banner" style="background:{bbg};border-color:{bbdr}">
                  <div>
                    <div class="banner-text" style="color:{bc}">{blabel}</div>
                    <div class="banner-sub" style="color:{bc}">{result['reason']}</div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

                # Session integrity
                integrity      = result.get("session_integrity", "STABLE")
                runtime_status = result.get("runtime_status", "CLEAN")
                int_map = {
                    "STABLE":      ("#3ecf80", "#071610", "#2a7a4a"),
                    "DEGRADING":   ("#f5b942", "#130f00", "#8a6800"),
                    "COMPROMISED": ("#f56060", "#130808", "#8a2222"),
                }
                ic, ibg, ibdr = int_map.get(integrity, int_map["STABLE"])
                int_labels = {
                    "STABLE":      "Session behaviour normal",
                    "DEGRADING":   "Session behaviour deteriorating",
                    "COMPROMISED": "Session integrity compromised",
                }
                st.markdown(f"""
                <div class="srow" style="background:{ibg};border-color:{ibdr}">
                  <span class="srow-label">Session Status</span>
                  <span style="color:{ic};font-family:'Rajdhani',sans-serif;
                               font-size:1rem;font-weight:700;letter-spacing:0.06em">
                    {int_labels.get(integrity, integrity)}
                  </span>
                </div>
                """, unsafe_allow_html=True)

                # Runtime alert
                if runtime_status == "ATTACK":
                    st.markdown(f"""
                    <div class="srow" style="background:#130808;border-color:#8a2222">
                      <span class="srow-label" style="color:#f56060">Alert</span>
                      <span style="color:#f56060">{result.get('signal_reason', '')}</span>
                    </div>""", unsafe_allow_html=True)
                elif runtime_status == "WARNING":
                    st.markdown(f"""
                    <div class="srow" style="background:#130f00;border-color:#8a6800">
                      <span class="srow-label" style="color:#f5b942">Warning</span>
                      <span style="color:#f5b942">{result.get('signal_reason', '')}</span>
                    </div>""", unsafe_allow_html=True)

                # Mutual auth
                ma_cls = "g" if result["mutual_auth_passed"] else "r"
                ma_val = "Verified" if result["mutual_auth_passed"] else "Failed"
                st.markdown(f"""
                <div class="srow">
                  <span class="srow-label">Station Identity</span>
                  <span class="{ma_cls}" style="font-family:'Rajdhani',sans-serif;
                               font-weight:700;font-size:0.95rem">{ma_val}</span>
                  <span class="srow-val" style="font-size:0.78rem">{result['mutual_auth_detail']}</span>
                </div>""", unsafe_allow_html=True)

                # Identity disclosure
                id_cls = "g" if result["identity_shared"] else "a"
                id_val = "Transmitted" if result["identity_shared"] else "Protected"
                id_sub = "Station passed verification" if result["identity_shared"] else "Withheld — station not fully trusted"
                st.markdown(f"""
                <div class="srow">
                  <span class="srow-label">Billing Identity</span>
                  <span class="{id_cls}" style="font-family:'Rajdhani',sans-serif;
                               font-weight:700;font-size:0.95rem">{id_val}</span>
                  <span class="srow-val" style="font-size:0.78rem">{id_sub}</span>
                </div>""", unsafe_allow_html=True)

            # ── SECTION 3: Signal breakdown ─────────────────────────────────
            st.markdown('<div class="sec-div"><span class="sec-label">Signal Analysis</span><span style="flex:1;border-top:1px solid #1e3228;margin-left:12px"></span></div>', unsafe_allow_html=True)

            sc1, sc2, sc3 = st.columns(3)

            def signal_card(col, label, sv, weight, detail, rtt_ms=None):
                bc  = "#3ecf80" if sv >= 0.8 else "#f5b942" if sv >= 0.5 else "#f56060"
                bg  = "#071610" if sv >= 0.8 else "#130f00" if sv >= 0.5 else "#130808"
                bdr = "#2a7a4a" if sv >= 0.8 else "#8a6800" if sv >= 0.5 else "#8a2222"
                pct = int(sv * 100)
                verdict = "PASS" if sv >= 0.8 else "WARN" if sv >= 0.5 else "FAIL"
                rtt_line = f'<div class="mdetail">{rtt_ms} ms average response</div>' if rtt_ms else ""
                col.markdown(f"""
                <div class="card" style="background:{bg};border:2px solid {bdr}">
                  <div class="mlabel">{label}</div>
                  <div style="font-family:'Share Tech Mono',monospace;font-size:2.6rem;
                              color:{bc};line-height:1;margin:0.3rem 0">{sv:.2f}</div>
                  <div style="margin:0.55rem 0;background:#0b100c;border-radius:2px;height:5px">
                    <div style="width:{pct}%;height:5px;background:{bc};border-radius:2px"></div>
                  </div>
                  <div style="font-family:'Rajdhani',sans-serif;font-size:0.85rem;font-weight:700;
                              color:{bc};letter-spacing:0.1em;margin-bottom:0.25rem">{verdict}</div>
                  <div class="mdetail">{detail}</div>
                  {rtt_line}
                </div>""", unsafe_allow_html=True)

            signal_card(sc1, "Certificate",    result["cert_score"],    "0.50", result["cert_detail"])
            signal_card(sc2, "Response Time",  result["latency_score"], "0.25", result["latency_detail"], result["avg_rtt_ms"])
            signal_card(sc3, "Power Delivery", result["probe_score"],   "0.25", result["probe_detail"])

            # Voltage chart — compact, supporting role
            if result["voltage_readings"]:
                readings = result["voltage_readings"]
                var    = statistics.variance(readings)
                mean_v = statistics.mean(readings)
                vc     = "#3ecf80" if result["probe_score"] >= 0.8 else "#f5b942" if result["probe_score"] >= 0.5 else "#f56060"

                st.markdown("<div style='margin-top:1rem'></div>", unsafe_allow_html=True)
                vcol1, vcol2 = st.columns([2, 1])
                with vcol1:
                    fig2 = go.Figure()
                    fig2.add_trace(go.Scatter(
                        y=readings, mode="lines+markers",
                        line=dict(color=vc, width=2),
                        marker=dict(size=5, color=vc),
                    ))
                    fig2.add_hline(y=400, line_dash="dot", line_color="#1e3228",
                        annotation_text="Requested: 400 V",
                        annotation_font_color="#4a7a5a",
                        annotation_font_size=11,
                        annotation_position="bottom right")
                    fig2.add_hline(y=mean_v, line_dash="dash", line_color=vc,
                        annotation_text=f"Mean: {mean_v:.1f} V",
                        annotation_font_color=vc,
                        annotation_font_size=11,
                        annotation_position="top right")
                    fig2.update_layout(
                        height=145, margin=dict(t=8, b=8, l=8, r=8),
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0b100c",
                        font=dict(family="Rajdhani", color="#5a8a6a", size=11),
                        yaxis=dict(gridcolor="#162420", zerolinecolor="#162420"),
                        xaxis=dict(gridcolor="#162420", title="Sample"),
                        showlegend=False,
                    )
                    st.plotly_chart(fig2, use_container_width=True)
                with vcol2:
                    st.markdown(f"""
                    <div class="card" style="margin-top:0.1rem">
                      <div class="mlabel">Voltage Variance</div>
                      <div style="font-family:'Share Tech Mono',monospace;font-size:1.7rem;
                                  color:{vc};line-height:1;margin:0.3rem 0">{var:.2f}</div>
                      <div class="mdetail">
                        Block threshold: 100<br>
                        Warn threshold: 20<br>
                        Deviation: {abs(mean_v-400):.2f} V
                      </div>
                    </div>""", unsafe_allow_html=True)

            # ── SECTION 4: Runtime monitoring ───────────────────────────────
            st.markdown('<div class="sec-div"><span class="sec-label">Behaviour Monitoring</span><span style="flex:1;border-top:1px solid #1e3228;margin-left:12px"></span></div>', unsafe_allow_html=True)

            sig_msgs  = result.get("signal_messages", [])
            sig_rsn   = result.get("signal_reason", "")
            integrity = result.get("session_integrity", "STABLE")
            runtime_s = result.get("runtime_status", "CLEAN")

            if sig_msgs:
                accepted   = sum(1 for m in sig_msgs if m["status"] == "ACCEPTED")
                suspicious = sum(1 for m in sig_msgs if m["status"] == "SUSPICIOUS")
                blocked    = sum(1 for m in sig_msgs if m["status"] == "BLOCKED")

                # Integrity badge
                int_map2 = {
                    "STABLE":      ("#3ecf80", "#071610", "#2a7a4a", "Session Stable"),
                    "DEGRADING":   ("#f5b942", "#130f00", "#8a6800", "Session Degrading"),
                    "COMPROMISED": ("#f56060", "#130808", "#8a2222", "Session Compromised"),
                }
                ic2, ibg2, ibdr2, ilbl2 = int_map2.get(integrity, int_map2["STABLE"])
                st.markdown(f"""
                <div class="int-badge" style="background:{ibg2};border-color:{ibdr2}">
                  <div class="int-label" style="color:{ic2}">{ilbl2}</div>
                  <div class="int-count" style="color:{ic2}">{len(sig_msgs)} messages monitored</div>
                </div>""", unsafe_allow_html=True)

                # Count cards
                sm1, sm2, sm3, sm4 = st.columns(4)
                for col, lbl, val, clr in [
                    (sm1, "Total",      len(sig_msgs), "#cdd5e0"),
                    (sm2, "Normal",     accepted,      "#3ecf80"),
                    (sm3, "Suspicious", suspicious,    "#f5b942"),
                    (sm4, "Blocked",    blocked,       "#f56060"),
                ]:
                    col.markdown(f"""
                    <div class="mini-count-card">
                      <div class="mini-count-val" style="color:{clr}">{val}</div>
                      <div class="mini-count-label">{lbl}</div>
                    </div>""", unsafe_allow_html=True)

                st.markdown("<div style='margin-top:0.7rem'></div>", unsafe_allow_html=True)

                # Streaming message table
                stream_ph = st.empty()
                rendered_rows = []
                sc_map  = {"ACCEPTED": "#3ecf80", "SUSPICIOUS": "#f5b942", "BLOCKED": "#f56060"}
                sbg_map = {"ACCEPTED": "transparent", "SUSPICIOUS": "#130f00", "BLOCKED": "#130808"}

                header_html = (
                    '<div style="display:flex;padding:6px 12px;border-bottom:2px solid #1e3228;'
                    'font-family:Rajdhani,sans-serif;font-size:12px;font-weight:700;color:#4a7a5a;'
                    'text-transform:uppercase;letter-spacing:0.1em">'
                    '<span style="min-width:34px">No.</span>'
                    '<span style="min-width:95px">Time</span>'
                    '<span style="min-width:190px">Message Type</span>'
                    '<span style="min-width:80px">Response</span>'
                    '<span style="min-width:115px">Result</span>'
                    '<span>Detail</span></div>'
                )

                def render_table(rows):
                    html = (
                        '<div style="background:#0b100c;border:2px solid #1e3228;border-radius:5px;overflow:hidden">'
                        + header_html + "".join(rows) + "</div>"
                    )
                    stream_ph.empty()
                    with stream_ph:
                        components.html(html, height=46 + len(rows) * 30, scrolling=False)

                for m in sig_msgs:
                    sc2  = sc_map.get(m["status"], "#cdd5e0")
                    sbg2 = sbg_map.get(m["status"], "transparent")
                    rtt_c = (
                        "#f56060" if m["response_time_ms"] >= 180
                        else "#f5b942" if m["response_time_ms"] >= 120
                        else "#3ecf80"
                    )
                    status_display = {
                        "ACCEPTED":  "Normal",
                        "SUSPICIOUS":"Suspicious",
                        "BLOCKED":   "Blocked",
                    }.get(m["status"], m["status"])
                    reason_s = (
                        f'<span style="color:#8a5050;font-size:11px;font-family:Share Tech Mono,monospace">'
                        f'{m["reason"]}</span>'
                        if m["reason"] else ""
                    )
                    row = (
                        f'<div style="display:flex;align-items:center;padding:4px 12px;'
                        f'border-bottom:1px solid #162420;background:{sbg2};'
                        f'font-family:Share Tech Mono,monospace;font-size:12px;line-height:2.1">'
                        f'<span style="color:#3a6a4a;min-width:34px">{m["seq"]:02d}</span>'
                        f'<span style="color:#4a8a5a;min-width:95px">{m["timestamp_ms"]}ms</span>'
                        f'<span style="color:#6aaa7a;min-width:190px">{m["type"]}</span>'
                        f'<span style="color:{rtt_c};min-width:80px">{m["response_time_ms"]}ms</span>'
                        f'<span style="color:{sc2};min-width:115px;font-family:Rajdhani,sans-serif;'
                        f'font-size:13px;font-weight:700">{status_display}</span>'
                        f'{reason_s}</div>'
                    )
                    rendered_rows.append(row)
                    render_table(rendered_rows)
                    time.sleep(0.08)

                # Reaction block
                if runtime_s == "ATTACK":
                    st.markdown(f"""
                    <div class="reaction-block" style="background:#130808;border-color:#8a2222">
                      <div class="reaction-title" style="color:#f56060">
                        Malicious activity detected — session restricted
                      </div>
                      <div class="reaction-detail" style="color:#aa6060">
                        {sig_rsn}<br>
                        Charging limited to 3 kW · Billing identity sealed · Session flagged
                      </div>
                    </div>""", unsafe_allow_html=True)
                elif runtime_s == "WARNING":
                    st.markdown(f"""
                    <div class="reaction-block" style="background:#130f00;border-color:#8a6800">
                      <div class="reaction-title" style="color:#f5b942">
                        Abnormal behaviour detected during charging
                      </div>
                      <div class="reaction-detail" style="color:#aa8840">
                        {sig_rsn}<br>
                        Trust score reduced · Monitoring continues · Driver notified
                      </div>
                    </div>""", unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="reaction-block" style="background:#071610;border-color:#2a7a4a">
                      <div class="reaction-title" style="color:#3ecf80">
                        All session signals normal — charging secure
                      </div>
                    </div>""", unsafe_allow_html=True)

            # System logs
            st.markdown("<div style='margin-top:0.9rem'></div>", unsafe_allow_html=True)
            with st.expander("Technical Logs", expanded=False):
                def colourise(line):
                    l = line.lower()
                    if any(w in l for w in ["pass", "allowed", "verified", "valid"]):        return f'<span class="lp">{line}</span>'
                    if any(w in l for w in ["fail", "block", "invalid", "error", "reject"]):  return f'<span class="lf">{line}</span>'
                    if any(w in l for w in ["warn", "elevated", "penalised", "safe mode"]):   return f'<span class="lw">{line}</span>'
                    if any(w in l for w in ["[ev]", "[trust]", "[signal]"]):                  return f'<span class="li">{line}</span>'
                    return f'<span class="ln">{line}</span>'
                log_html = "<br>".join(colourise(ln) for ln in result["logs"])
                st.markdown(f'<div class="lbox">{log_html}</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — THREAT MODEL
# ═════════════════════════════════════════════════════════════════════════════
with tab_threat:
    st.markdown("<div style='height:0.7rem'></div>", unsafe_allow_html=True)
    tm1, tm2 = st.columns([1, 1], gap="large")

    with tm1:
        st.markdown('<div class="sec-heading">System Risks Overview</div>', unsafe_allow_html=True)
        for key, val in [
            ("Attack Entry",   "A rogue station broadcasts on the same power line channel as a legitimate charger. Any passing vehicle can be targeted."),
            ("How It Works",   "The vehicle connects without verifying the station. The fake station accepts this and impersonates a real charger."),
            ("What Is Stolen", "Billing identity, vehicle identifier, session credentials. The attacker can also alter charging parameters."),
            ("Who Is At Risk",  "Any electric vehicle using the Plug and Charge standard without additional verification."),
            ("Real Impact",    "Financial fraud · location tracking · potential control over charging behaviour · access to vehicle systems"),
        ]:
            st.markdown(f"""
            <div class="tcard">
              <div style="display:flex;gap:14px">
                <span class="tkey">{key}</span>
                <span class="tval">{val}</span>
              </div>
            </div>""", unsafe_allow_html=True)

    with tm2:
        st.markdown('<div class="sec-heading">How GhostWire Responds</div>', unsafe_allow_html=True)
        for label, col, detail in [
            ("Fully Blocked",    "#f56060", "Score below 50: the vehicle refuses to connect. No power flows. The user is notified of the threat."),
            ("Restricted Mode",  "#f5b942", "Score 50 to 79: charging is allowed at low power only. Billing data is withheld. Driver is alerted."),
            ("False Alarms",     "#6090f0", "When verification servers are unreachable, the system degrades gracefully — it never blocks legitimate charging unnecessarily."),
            ("Identity Privacy", "#3ecf80", "The vehicle only shares its billing identity after the station passes all verification checks."),
            ("Works Offline",    "#3ecf80", "The entire verification process runs on the vehicle. No internet connection or cloud service required."),
        ]:
            st.markdown(f"""
            <div class="card" style="margin-bottom:0.6rem">
              <div style="font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:700;
                          color:{col};text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.35rem">{label}</div>
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.84rem;
                          color:#6a9a7a;line-height:1.65">{detail}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)
        st.markdown('<div style="font-family:Rajdhani,sans-serif;font-size:0.9rem;font-weight:700;color:#4a7a5a;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:0.45rem">How Trust Is Calculated</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="card">
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.85rem;color:#6a9a7a;line-height:2.5">
            <span style="color:#8070e0">Trust Score</span>
            = (Certificate × <span style="color:#3ecf80">0.50</span>)
            + (Response Time × <span style="color:#f5b942">0.25</span>)
            + (Power Stability × <span style="color:#f5b942">0.25</span>)
            <br>
            <span style="color:#4a7a5a">If certificate fails:</span>
            score is forced to zero — no exceptions
            <br>
            <span style="color:#3ecf80">80 or above</span> — Connection allowed
            &nbsp;&nbsp;
            <span style="color:#f5b942">50 to 79</span> — Restricted mode
            &nbsp;&nbsp;
            <span style="color:#f56060">Below 50</span> — Blocked
          </div>
        </div>""", unsafe_allow_html=True)
