import streamlit as st
import math
import re
import time
import random
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


def format_time(seconds):
    if seconds < 1:       return "< 1 second"
    if seconds < 60:      return f"{seconds:.1f} sec"
    if seconds < 3600:    return f"{seconds/60:.1f} min"
    if seconds < 86400:   return f"{seconds/3600:.1f} hrs"
    if seconds < 2592000: return f"{seconds/86400:.1f} days"
    if seconds < 31536000:return f"{seconds/2592000:.1f} months"
    if seconds < 3.15e9:  return f"{seconds/31536000:.1f} years"
    if seconds < 3.15e12: return f"{seconds/3.15e9:.1f} K years"
    return f"{seconds/3.15e13:.1f} M years"


from analyzer import (
    calculate_entropy,
    estimate_crack_times,
    check_common_password,
    get_strength_label,
    get_character_pool_size,
    simulate_crack,
    get_password_feedback,
)

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PassCrack Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    background-color: #090e1a;
    color: #c8d8e8;
    font-family: 'Rajdhani', sans-serif;
}

.main { background-color: #090e1a; }

h1, h2, h3 { font-family: 'Share Tech Mono', monospace; color: #00f0ff; }

.stTextInput > div > div > input {
    background: #0d1829 !important;
    border: 1px solid #00f0ff44 !important;
    border-radius: 4px !important;
    color: #00f0ff !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 1.2rem !important;
    letter-spacing: 0.15em !important;
    padding: 12px 16px !important;
}

.stTextInput > div > div > input:focus {
    border-color: #00f0ff !important;
    box-shadow: 0 0 12px #00f0ff44 !important;
}

.metric-card {
    background: #0d1829;
    border: 1px solid #00f0ff22;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    margin: 8px 0;
}

.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #00f0ff;
    display: block;
}

.metric-label {
    font-size: 0.85rem;
    color: #7a9bb0;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}

.strength-bar-container {
    background: #0d1829;
    border: 1px solid #00f0ff22;
    border-radius: 8px;
    padding: 24px;
    margin: 16px 0;
}

.status-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.1em;
    font-weight: bold;
}

.crack-sim-card {
    background: #0a1220;
    border: 1px solid #ff003344;
    border-radius: 8px;
    padding: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: #ff6666;
    line-height: 1.8;
}

.feedback-item {
    padding: 8px 12px;
    margin: 4px 0;
    border-left: 3px solid;
    border-radius: 0 4px 4px 0;
    font-size: 0.9rem;
}

.section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #00f0ff;
    font-size: 0.75rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    border-bottom: 1px solid #00f0ff22;
    padding-bottom: 8px;
    margin: 24px 0 16px 0;
}

.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    color: #00f0ff;
    text-shadow: 0 0 30px #00f0ff66;
    margin-bottom: 4px;
}

.hero-sub {
    color: #5a7a8a;
    font-size: 1rem;
    letter-spacing: 0.1em;
}

div[data-testid="stMetricValue"] {
    font-family: 'Share Tech Mono', monospace !important;
    color: #00f0ff !important;
}
</style>
""", unsafe_allow_html=True)

# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown('<div class="hero-title">🔐 PASSCRACK ANALYZER</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-sub">[ See exactly how fast a hacker can crack your password ]</div>', unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# ─── Password Input ───────────────────────────────────────────────────────────
col_input, col_space = st.columns([3, 1])
with col_input:
    password = st.text_input(
        "Enter a password to analyze",
        type="password",
        placeholder="Type your password here...",
        label_visibility="collapsed",
    )

    show_password = st.checkbox("👁 Reveal password", value=False)

if show_password and password:
    st.code(password, language=None)

# ─── Analysis ─────────────────────────────────────────────────────────────────
if not password:
    st.markdown("""
    <div style='text-align:center; padding: 60px 20px; color: #2a4a5a;'>
        <div style='font-family: Share Tech Mono, monospace; font-size: 3rem;'>_</div>
        <div style='font-family: Share Tech Mono, monospace; letter-spacing: 0.2em;'>AWAITING INPUT</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# Run analysis
entropy        = calculate_entropy(password)
crack_times    = estimate_crack_times(password)
is_common      = check_common_password(password)
strength_score = min(int(entropy / 1.28), 100)  # 0-100
strength_label, strength_color = get_strength_label(entropy, is_common)
feedback       = get_password_feedback(password)
pool_size      = get_character_pool_size(password)

# ─── Top Metrics Row ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">// ANALYSIS RESULTS</div>', unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="metric-card">
        <span class="metric-value">{entropy:.1f}</span>
        <span class="metric-label">Entropy (bits)</span>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="metric-card">
        <span class="metric-value">{len(password)}</span>
        <span class="metric-label">Length</span>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="metric-card">
        <span class="metric-value">{pool_size}</span>
        <span class="metric-label">Char Pool Size</span>
    </div>""", unsafe_allow_html=True)

with c4:
    common_text = "YES ⚠️" if is_common else "NO ✓"
    common_color = "#ff4444" if is_common else "#00ff88"
    st.markdown(f"""
    <div class="metric-card">
        <span class="metric-value" style="color:{common_color}; font-size:1.5rem;">{common_text}</span>
        <span class="metric-label">In Common List</span>
    </div>""", unsafe_allow_html=True)

# ─── Strength Meter ───────────────────────────────────────────────────────────
st.markdown('<div class="section-header">// STRENGTH METER</div>', unsafe_allow_html=True)

fig_gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=strength_score,
    number={"suffix": "%", "font": {"family": "Share Tech Mono", "color": strength_color, "size": 40}},
    gauge={
        "axis": {"range": [0, 100], "tickfont": {"family": "Share Tech Mono", "color": "#5a7a8a"}},
        "bar": {"color": strength_color, "thickness": 0.3},
        "bgcolor": "#0d1829",
        "borderwidth": 1,
        "bordercolor": "#1a2a3a",
        "steps": [
            {"range": [0, 25],  "color": "#1a0a0a"},
            {"range": [25, 50], "color": "#1a120a"},
            {"range": [50, 75], "color": "#0a150a"},
            {"range": [75, 100],"color": "#0a1515"},
        ],
        "threshold": {
            "line": {"color": strength_color, "width": 3},
            "thickness": 0.8,
            "value": strength_score,
        },
    },
    title={"text": f"<b>{strength_label}</b>", "font": {"family": "Share Tech Mono", "color": strength_color, "size": 18}},
))
fig_gauge.update_layout(
    paper_bgcolor="#0d1829",
    plot_bgcolor="#0d1829",
    height=280,
    margin=dict(t=40, b=20, l=40, r=40),
)
st.plotly_chart(fig_gauge, use_container_width=True)

# ─── Crack Time Charts ────────────────────────────────────────────────────────
st.markdown('<div class="section-header">// ESTIMATED CRACK TIMES BY ATTACK METHOD</div>', unsafe_allow_html=True)

attacks = list(crack_times.keys())
raw_seconds = list(crack_times.values())
display_labels = [format_time(s) for s in raw_seconds]

# Color by danger level
bar_colors = []
for s in raw_seconds:
    if s < 60:           bar_colors.append("#ff2244")
    elif s < 86400:      bar_colors.append("#ff8800")
    elif s < 31536000:   bar_colors.append("#ffdd00")
    elif s < 3.15e9:     bar_colors.append("#88ff44")
    else:                bar_colors.append("#00ff88")

log_vals = [max(math.log10(max(s, 0.001)), 0) for s in raw_seconds]

fig_bar = go.Figure(go.Bar(
    x=attacks,
    y=log_vals,
    marker_color=bar_colors,
    marker_line_color="#1a2a3a",
    marker_line_width=1,
    text=display_labels,
    textposition="outside",
    textfont={"family": "Share Tech Mono", "color": "#c8d8e8", "size": 11},
    hovertemplate="<b>%{x}</b><br>Crack time: %{text}<extra></extra>",
))

fig_bar.update_layout(
    paper_bgcolor="#0d1829",
    plot_bgcolor="#090e1a",
    height=360,
    margin=dict(t=30, b=20, l=60, r=20),
    xaxis=dict(
        tickfont={"family": "Share Tech Mono", "color": "#5a7a8a", "size": 10},
        gridcolor="#111e2e",
        linecolor="#1a2a3a",
    ),
    yaxis=dict(
        title="log₁₀(seconds)",
        tickfont={"family": "Share Tech Mono", "color": "#5a7a8a"},
        gridcolor="#111e2e",
        linecolor="#1a2a3a",
        tickvals=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15],
        ticktext=["1s","10s","1.7m","16m","2.7h","1.1d","11d","4mo","3.2y","31y","317y","31Ky","31My"],
    ),
    showlegend=False,
)
fig_bar.update_traces(width=0.5)
st.plotly_chart(fig_bar, use_container_width=True)

# ─── Crack Simulation ─────────────────────────────────────────────────────────
st.markdown('<div class="section-header">// LIVE CRACK SIMULATION</div>', unsafe_allow_html=True)

col_sim, col_feedback = st.columns([1, 1])

with col_sim:
    if st.button("▶  RUN SIMULATION", use_container_width=True):
        sim_lines = simulate_crack(password)
        sim_output = st.empty()
        displayed = []
        for line in sim_lines:
            displayed.append(line)
            sim_output.markdown(
                "<div class='crack-sim-card'>" + "<br>".join(displayed) + "</div>",
                unsafe_allow_html=True,
            )
            time.sleep(0.07)
    else:
        st.markdown("""
        <div class='crack-sim-card' style='color:#2a4a5a; text-align:center; padding:40px;'>
            [ PRESS RUN TO START SIMULATION ]
        </div>""", unsafe_allow_html=True)

# ─── Password Feedback ────────────────────────────────────────────────────────
with col_feedback:
    st.markdown('<div style="font-family: Share Tech Mono, monospace; font-size: 0.7rem; letter-spacing: 0.2em; color: #00f0ff; margin-bottom:12px;">// IMPROVEMENT TIPS</div>', unsafe_allow_html=True)
    for item in feedback:
        icon  = item["icon"]
        msg   = item["msg"]
        color = item["color"]
        bg    = item["bg"]
        st.markdown(f"""
        <div class="feedback-item" style="border-color:{color}; background:{bg}; color:#c8d8e8;">
            {icon} {msg}
        </div>""", unsafe_allow_html=True)

# ─── Character Distribution ───────────────────────────────────────────────────
st.markdown('<div class="section-header">// CHARACTER COMPOSITION</div>', unsafe_allow_html=True)

char_counts = {
    "Uppercase": sum(1 for c in password if c.isupper()),
    "Lowercase": sum(1 for c in password if c.islower()),
    "Digits":    sum(1 for c in password if c.isdigit()),
    "Symbols":   sum(1 for c in password if not c.isalnum()),
}
char_counts = {k: v for k, v in char_counts.items() if v > 0}

if char_counts:
    fig_pie = go.Figure(go.Pie(
        labels=list(char_counts.keys()),
        values=list(char_counts.values()),
        hole=0.55,
        marker=dict(
            colors=["#00aaff", "#00f0ff", "#88ff44", "#ff8800"],
            line=dict(color="#090e1a", width=2),
        ),
        textfont={"family": "Share Tech Mono", "color": "#c8d8e8"},
        hovertemplate="<b>%{label}</b>: %{value} chars (%{percent})<extra></extra>",
    ))
    fig_pie.update_layout(
        paper_bgcolor="#0d1829",
        plot_bgcolor="#0d1829",
        height=300,
        margin=dict(t=20, b=20, l=20, r=20),
        legend=dict(font=dict(family="Share Tech Mono", color="#5a7a8a"), bgcolor="#0d1829"),
        annotations=[dict(
            text=f"<b>{len(password)}</b><br><span style='font-size:10px'>chars</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(family="Share Tech Mono", color="#00f0ff", size=18),
        )],
    )
    st.plotly_chart(fig_pie, use_container_width=True)

# ─── Footer ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style='margin-top: 60px; border-top: 1px solid #0d2030; padding: 40px 0 30px;'>

  <div style='text-align:center; margin-bottom: 20px;'>
    <span style='
      font-family: Share Tech Mono, monospace;
      font-size: 0.7rem;
      letter-spacing: 0.25em;
      color: #2a4a5a;
      text-transform: uppercase;
    '>— Built by —</span>
  </div>

  <div style='text-align:center; margin-bottom: 6px;'>
    <span style='
      font-family: Share Tech Mono, monospace;
      font-size: 1.6rem;
      color: #00f0ff;
      text-shadow: 0 0 20px #00f0ff55;
      letter-spacing: 0.12em;
    '>DIYA RATHOD</span>
  </div>

  <div style='text-align:center; margin-bottom: 28px;'>
    <span style='
      font-family: Share Tech Mono, monospace;
      font-size: 0.75rem;
      color: #1a6a7a;
      letter-spacing: 0.3em;
      text-transform: uppercase;
    '>[ SECURITY RESEARCHER ]</span>
  </div>

  <div style='text-align:center; margin-bottom: 30px;'>
    <a href='https://www.linkedin.com/in/diya-rathod' target='_blank' style='
      font-family: Share Tech Mono, monospace;
      font-size: 0.7rem;
      color: #0077b5;
      letter-spacing: 0.15em;
      text-decoration: none;
      border: 1px solid #0077b522;
      padding: 6px 18px;
      border-radius: 3px;
    '>🔗 LINKEDIN</a>
    &nbsp;&nbsp;
    <a href='https://github.com/diya-rathod' target='_blank' style='
      font-family: Share Tech Mono, monospace;
      font-size: 0.7rem;
      color: #5a7a8a;
      letter-spacing: 0.15em;
      text-decoration: none;
      border: 1px solid #1a2a3a;
      padding: 6px 18px;
      border-radius: 3px;
    '>⌥ GITHUB</a>
  </div>

  <div style='text-align:center; color:#1a3a4a; font-family: Share Tech Mono, monospace; font-size:0.65rem; letter-spacing:0.2em;'>
    PASSCRACK ANALYZER v1.0 — FOR EDUCATIONAL PURPOSES ONLY &nbsp;|&nbsp; NEVER TEST OTHER PEOPLE'S PASSWORDS
  </div>

</div>
""", unsafe_allow_html=True)



