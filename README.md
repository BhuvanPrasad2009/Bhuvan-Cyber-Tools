# Bhuvan-Cyber-Tools
 Python Password Security Tester
#!/usr/bin/env python3
"""Bhuvan Cyber Tools - Password Security Tester

Checks how strong a password is, fully offline by default.
  python password_tester.py            -> asks for a password (hidden typing)
  python password_tester.py --breach   -> also checks the Have I Been Pwned list
  python password_tester.py --generate -> makes a strong random password

The password is never printed, saved, or passed on the command line.
"""
import argparse
import getpass
import hashlib
import math
import re
import secrets
import string
import sys
import urllib.request

COMMON = {
    "password", "123456", "12345678", "123456789", "1234567", "12345", "qwerty",
    "qwerty123", "abc123", "letmein", "welcome", "admin", "login", "iloveyou",
    "monkey", "dragon", "football", "baseball", "master", "sunshine", "princess",
    "shadow", "superman", "batman", "trustno1", "passw0rd", "starwars", "hello",
    "freedom", "whatever", "qazwsx", "zaq12wsx", "michael", "charlie", "donald",
    "mustang", "access", "flower", "hottie", "loveme", "ninja", "azerty",
    "1q2w3e4r", "1qaz2wsx", "654321", "111111", "000000", "666666", "121212",
    "computer", "internet", "cricket", "india123", "changeme", "secret",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans("@43 10$5!7".replace(" ", ""), "aaeiossit")
GUESSES_PER_SECOND = 1e10  # fast offline attack on a weak hash


def pool_size(pw):
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c in string.punctuation for c in pw):
        pool += 32
    if any(ord(c) > 127 or c == " " for c in pw):
        pool += 32
    return max(pool, 1)


def find_issues(pw):
    """Return a list of (message, bits_penalty) for weak patterns."""
    issues = []
    low = pw.lower()
    trimmed = low.rstrip(string.digits + string.punctuation)
    candidates = {low, low.translate(LEET), trimmed, trimmed.translate(LEET)}

    if candidates & COMMON:
        issues.append(("Based on a very common password", 40))
    if re.search(r"(.)\1{2,}", pw):
        issues.append(("Same character repeated 3+ times", 8))
    if re.fullmatch(r"(.{2,}?)\1+", pw):
        issues.append(("A short chunk repeated over and over", 15))
    if re.search(r"(19|20)\d{2}", pw):
        issues.append(("Contains a year (easy to guess)", 6))

    for i in range(len(low) - 2):
        a, b, c = low[i], low[i + 1], low[i + 2]
        if a.isalnum() and ord(b) - ord(a) == ord(c) - ord(b) in (1, -1):
            issues.append(("Simple sequence like abc or 321", 8))
            break

    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            if any(r[i:i + 4] in low for i in range(len(r) - 3)):
                issues.append(("Keyboard pattern like qwer or asdf", 10))
                break
        else:
            continue
        break
    return issues


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365),
             ("year", 1000), ("thousand years", 1000), ("million years", 1000)]
    value = seconds
    for name, size in units:
        if value < size:
            return f"about {value:.0f} {name}{'s' if value >= 1.5 and not name.endswith('years') else ''}"
        value /= size
    return "billions of years or more"


def analyze(pw):
    pool = pool_size(pw)
    raw_bits = len(pw) * math.log2(pool)
    issues = find_issues(pw)
    bits = max(raw_bits - sum(p for _, p in issues), 0)
    seconds = (2 ** min(bits, 200)) / 2 / GUESSES_PER_SECOND

    if bits < 28:
        label = "Very weak"
    elif bits < 40:
        label = "Weak"
    elif bits < 60:
        label = "Fair"
    elif bits < 80:
        label = "Strong"
    else:
        label = "Very strong"

    tips = []
    if len(pw) < 12:
        tips.append("Use at least 12 characters; length matters most.")
    if len(set(pw)) < len(pw) * 0.6:
        tips.append("Use more different characters.")
    if pool < 62:
        tips.append("Mix upper and lower case, numbers, and symbols.")
    if issues:
        tips.append("Avoid the patterns listed above.")
    tips.append("Best: a long passphrase of 4+ random words, unique per site.")
    return {"length": len(pw), "bits": bits, "label": label,
            "time": human_time(seconds), "issues": [m for m, _ in issues], "tips": tips}


def breach_count(pw):
    """Check Have I Been Pwned. Only the first 5 chars of the SHA-1 hash leave your device."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "Bhuvan-Cyber-Tools-PasswordTester"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        for line in resp.read().decode().splitlines():
            h, _, count = line.partition(":")
            if h == suffix:
                return int(count)
    return 0


def generate(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*-_=+?" for c in pw)):
            return pw


def main():
    ap = argparse.ArgumentParser(description="Password Security Tester")
    ap.add_argument("--breach", action="store_true",
                    help="also check the Have I Been Pwned breach list (needs internet)")
    ap.add_argument("--generate", nargs="?", const=16, type=int, metavar="LENGTH",
                    help="generate a strong random password (default length 16)")
    args = ap.parse_args()

    if args.generate:
        print(generate(max(args.generate, 12)))
        return

    pw = getpass.getpass("Enter password to test (hidden): ")
    if not pw:
        sys.exit("No password entered.")

    r = analyze(pw)
    print(f"\nStrength : {r['label']}")
    print(f"Length   : {r['length']} characters")
    print(f"Entropy  : ~{r['bits']:.0f} bits")
    print(f"Crack time (fast offline attack): {r['time']}")

    if r["issues"]:
        print("\nProblems found:")
        for m in r["issues"]:
            print(f"  - {m}")

    if args.breach:
        try:
            n = breach_count(pw)
            print(f"\nBreach check: found in {n:,} known leaks. Do not use it." if n
                  else "\nBreach check: not found in known leaks.")
        except Exception as e:  # network errors etc.
            print(f"\nBreach check failed: {e}")

    print("\nNote: this is an estimate. It does not check every dictionary word,")
    print("so use --breach for a real-world check.")
    print("\nTips:")
    for t in r["tips"]:
        print(f"  - {t}")


if __name__ == "__main__":
    main()