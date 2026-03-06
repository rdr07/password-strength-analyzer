"""
analyzer.py — Core engine for PassCrack Analyzer
Handles: entropy, crack time estimation, common password list, simulation, feedback
"""

import math
import re
import random
import string
import time

# ─── Top 200 most common passwords ────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "admin", "login",
    "welcome", "solo", "princess", "qwerty123", "admin123", "1q2w3e4r", "hello",
    "charlie", "donald", "password2", "qwertyuiop", "nintendo", "dragon1", "test",
    "pass", "azerty", "test1", "111111", "121212", "1234", "123456789", "12345",
    "0987654321", "1111", "000000", "55555", "666666", "77777777", "88888888",
    "987654321", "99999999", "iloveyou1", "batman", "pass123", "hockey", "ranger",
    "daniel", "starwars", "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "zxcvbn", "samsung", "jordan", "harley", "ranger1",
    "dakota", "maggie", "hunter", "buster", "soccer", "killer", "superman1",
    "thunder", "ginger", "hammer", "silver", "william", "dallas", "yankees",
    "hello123", "scooter", "cheese", "matrix", "internet", "service", "pokemon",
    "yellow", "phoenix", "tiger", "tucker", "chelsea", "manchester", "liverpool",
    "password!", "asdfgh", "asdfghjkl", "zxcvbnm", "trustme", "love", "secret",
    "asdf", "ninja", "asdfasdf", "snoopy", "cookie", "mustang", "access",
    "flower", "summer", "hockey1", "sexy", "android", "google", "apple", "iphone",
}


def get_character_pool_size(password: str) -> int:
    """Return the effective character pool size based on characters used."""
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password): pool += 32
    if re.search(r'[^\x00-\x7F]', password): pool += 100  # Unicode bonus
    return max(pool, 26)


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy (bits).
    Uses character pool size × length, with a bonus for mixed types.
    """
    if not password:
        return 0.0
    pool = get_character_pool_size(password)
    entropy = len(password) * math.log2(pool)
    # Bonus for using diverse character classes
    classes = sum([
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[0-9]', password)),
        bool(re.search(r'[^a-zA-Z0-9]', password)),
    ])
    entropy += (classes - 1) * 6  # up to +18 bits for full diversity
    return round(entropy, 2)


def estimate_crack_times(password: str) -> dict:
    """
    Return dict of attack_method → crack_time_seconds.
    All estimates assume worst-case (full search through half keyspace on average).
    """
    pool = get_character_pool_size(password)
    length = len(password)
    keyspace = pool ** length

    # Guesses per second for each attack type
    attack_rates = {
        "Online Attack\n(throttled)":      100,           # 100/s with lockout
        "Online Attack\n(no lockout)":      10_000,        # 10K/s
        "Offline Attack\n(slow hash bcrypt)": 10_000,      # 10K/s (bcrypt)
        "Offline Attack\n(MD5 GPU)":        10_000_000_000, # 10B/s
        "Offline Attack\n(fast hash SHA1)": 1_000_000_000, # 1B/s
        "Distributed\nCluster (NSA-tier)":  100_000_000_000_000,  # 100T/s
    }

    # Average attempts = keyspace / 2
    avg_attempts = keyspace / 2

    times = {}
    for method, rate in attack_rates.items():
        seconds = avg_attempts / rate
        times[method] = seconds

    return times


def check_common_password(password: str) -> bool:
    """Return True if password is in the common passwords list."""
    return password.lower() in COMMON_PASSWORDS


def get_strength_label(entropy: float, is_common: bool) -> tuple[str, str]:
    """Return (label, hex_color) for the given entropy."""
    if is_common:
        return "COMPROMISED", "#ff0044"
    if entropy < 28:
        return "VERY WEAK", "#ff2244"
    if entropy < 40:
        return "WEAK", "#ff6600"
    if entropy < 55:
        return "MODERATE", "#ffcc00"
    if entropy < 75:
        return "STRONG", "#88ff44"
    return "VERY STRONG", "#00ff88"


def get_password_feedback(password: str) -> list[dict]:
    """Return list of feedback items with icon, message, color, bg."""
    tips = []

    def tip(icon, msg, good=True):
        color = "#00ff88" if good else "#ff6644"
        bg    = "#0a1a0a" if good else "#1a0a0a"
        tips.append({"icon": icon, "msg": msg, "color": color, "bg": bg})

    if len(password) < 8:
        tip("✗", "Too short — use at least 12 characters", good=False)
    elif len(password) < 12:
        tip("△", "Short — 12+ characters is much safer", good=False)
    else:
        tip("✓", f"Good length ({len(password)} chars)", good=True)

    if re.search(r'[A-Z]', password):
        tip("✓", "Contains uppercase letters", good=True)
    else:
        tip("✗", "Add uppercase letters (A-Z)", good=False)

    if re.search(r'[a-z]', password):
        tip("✓", "Contains lowercase letters", good=True)
    else:
        tip("✗", "Add lowercase letters (a-z)", good=False)

    if re.search(r'[0-9]', password):
        tip("✓", "Contains digits", good=True)
    else:
        tip("✗", "Add numbers (0-9)", good=False)

    if re.search(r'[^a-zA-Z0-9]', password):
        tip("✓", "Contains special characters", good=True)
    else:
        tip("✗", "Add symbols (!@#$%^&*...)", good=False)

    if check_common_password(password):
        tip("⚠", "This is a known common password!", good=False)

    # Detect patterns
    if re.search(r'(.)\1{2,}', password):
        tip("△", "Repeated characters detected (e.g. aaa)", good=False)

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|wer|ert)', password.lower()):
        tip("△", "Sequential pattern detected (e.g. 123, abc)", good=False)

    if len(password) >= 16:
        tip("✓", "Excellent length — very hard to brute-force", good=True)

    if not tips:
        tip("✓", "Password looks decent!", good=True)

    return tips


def simulate_crack(password: str) -> list[str]:
    """
    Generate a list of terminal-style lines simulating a cracking attempt.
    Returns instantly (no sleep); caller handles timing.
    """
    lines = []
    entropy = calculate_entropy(password)
    is_common = check_common_password(password)
    pool = get_character_pool_size(password)
    keyspace = pool ** len(password)

    lines.append("$ ./hashcat --mode=0 --attack=3 target.hash")
    lines.append("")
    lines.append(f"[*] Target hash loaded...")
    lines.append(f"[*] Password length: {len(password)} chars")
    lines.append(f"[*] Estimated keyspace: {keyspace:.2e}")
    lines.append(f"[*] Entropy: {entropy:.1f} bits")
    lines.append("")

    if is_common:
        lines.append("[!] Checking wordlist: rockyou.txt")
        lines.append("[!] >> MATCH FOUND IN DICTIONARY <<")
        lines.append(f'[!] PASSWORD CRACKED: "{password}"')
        lines.append("[!] Time elapsed: 0.003 seconds")
        return lines

    # Stage 1: dictionary
    lines.append("[*] Stage 1 — Dictionary attack (rockyou.txt)...")
    sample_words = ["password", "dragon123", "letmein", "football", "sunshine"]
    for w in random.sample(sample_words, min(3, len(sample_words))):
        lines.append(f"    Trying: {w}{'*' * random.randint(1,3)}  [MISS]")
    lines.append("[-] Dictionary: exhausted. No match.")
    lines.append("")

    # Stage 2: rule-based
    lines.append("[*] Stage 2 — Rule-based mutations...")
    for _ in range(3):
        fake = ''.join(random.choices(string.ascii_letters + string.digits, k=len(password)))
        lines.append(f"    Trying: {fake}  [MISS]")
    lines.append("[-] Rules: exhausted. No match.")
    lines.append("")

    # Stage 3: brute force
    lines.append("[*] Stage 3 — GPU brute-force (RTX 4090)...")
    lines.append(f"[*] Rate: 10,000,000,000 guesses/sec")

    crack_seconds = (keyspace / 2) / 10_000_000_000
    if crack_seconds < 60:
        lines.append(f"[!] ETA: {crack_seconds:.2f} seconds")
    elif crack_seconds < 86400:
        lines.append(f"[!] ETA: {crack_seconds/60:.1f} minutes")
    elif crack_seconds < 31536000:
        lines.append(f"[!] ETA: {crack_seconds/86400:.1f} days")
    else:
        lines.append(f"[!] ETA: {crack_seconds/31536000:.1f} YEARS")

    if entropy >= 60:
        lines.append("")
        lines.append("[×] Attack aborted — exceeds heat death of universe")
        lines.append("[✓] Password is effectively uncrackable with current hardware.")
    elif entropy >= 40:
        lines.append("")
        lines.append("[△] Attack ongoing — this will take a very long time.")
        lines.append("[△] Password is reasonably secure but not unbreakable.")
    else:
        # simulate finding it
        progress_chars = list(password)
        cracked = ['_'] * len(password)
        lines.append("")
        for i, ch in enumerate(progress_chars):
            cracked[i] = ch
            lines.append(f"    Progress: {''.join(cracked)}  [{int((i+1)/len(password)*100)}%]")
        lines.append(f'[!] PASSWORD CRACKED: "{password}"')
        lines.append(f"[!] Total time: simulated")

    return lines
