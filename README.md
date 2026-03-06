# 🔐 PassCrack Analyzer

> **"See exactly how fast a hacker can crack your password."**

A cybersecurity dashboard that analyzes password strength using real cryptographic metrics — entropy calculation, brute-force time estimation, common password detection, and a live crack simulation.

---

## Features

| Feature | Description |
|---|---|
| **Entropy Calculator** | Shannon entropy in bits — the real measure of randomness |
| **Crack Time Estimator** | 6 attack methods from throttled online to NSA-tier distributed clusters |
| **Common Password Detector** | Flags passwords found in breach databases (rockyou-style) |
| **Crack Simulation** | Terminal-style simulation of a real hashcat attack |
| **Strength Gauge** | Visual 0–100% meter with color-coded verdict |
| **Character Composition** | Pie chart of uppercase / lowercase / digits / symbols |
| **Improvement Tips** | Actionable, real-time feedback |

---

## Quick Start

```bash
# 1. Clone or download this folder
cd password_analyzer

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
streamlit run app.py
```

Then open **http://localhost:8501** in your browser.

---

## Project Structure

```
password_analyzer/
├── app.py          # Streamlit UI — all visuals, layout, charts
├── analyzer.py     # Core engine — entropy, crack times, simulation
├── requirements.txt
└── README.md
```

---

## How the Math Works

### Entropy
```
entropy = length × log₂(pool_size) + diversity_bonus
```
- `pool_size` = how many distinct character types are used (lowercase=26, uppercase=26, digits=10, symbols=32)
- Diversity bonus = up to +18 bits for using all 4 character classes

### Crack Time
```
avg_guesses = pool_size^length / 2
crack_time  = avg_guesses / guesses_per_second
```

| Attack Method | Speed |
|---|---|
| Online (throttled) | 100/s |
| Online (no lockout) | 10,000/s |
| Offline bcrypt | 10,000/s |
| Offline SHA-1 GPU | 1,000,000,000/s |
| Offline MD5 GPU | 10,000,000,000/s |
| Distributed cluster | 100,000,000,000,000/s |

---

## Tech Stack

- **Python 3.10+**
- **Streamlit** — dashboard framework
- **Plotly** — interactive charts (gauge, bar, pie)
- No external APIs, no data sent anywhere — **100% local**

---

## LinkedIn Post

> I built a tool that shows how fast hackers can crack your password.
>
> Type in any password and it tells you:
> - Entropy (real cryptographic strength in bits)
> - How long it takes 6 different attack methods to crack it
> - Whether it's in a known breach list
> - A live terminal simulation of a hashcat attack
>
> Built with Python + Streamlit + Plotly in one day.
>
> 🔗 GitHub: [your link here]
> #cybersecurity #python #100DaysOfCode #buildinpublic #infosec

---

*For educational purposes only. Never test other people's passwords.*
