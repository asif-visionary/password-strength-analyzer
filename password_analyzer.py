import math
import random
import re
import sqlite3
import string
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ======================================================
# CONFIGURATION
# ======================================================

DICTIONARY_FILE = "xato-net-10-million-passwords-1000000.txt"
DATABASE_FILE = "password_history.db"

ph = PasswordHasher()

COMMON_PASSWORDS = set()
PASSWORD_RANKS = {}

# ======================================================
# DATABASE
# ======================================================

def initialize_database():

    conn = sqlite3.connect(DATABASE_FILE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_password_hash(password_hash):

    conn = sqlite3.connect(DATABASE_FILE)

    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO password_history(password_hash) VALUES (?)",
        (password_hash,)
    )

    conn.commit()
    conn.close()


def get_all_password_hashes():

    conn = sqlite3.connect(DATABASE_FILE)

    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM password_history"
    )

    hashes = [row[0] for row in cursor.fetchall()]

    conn.close()

    return hashes

# ======================================================
# DICTIONARY LOADING
# ======================================================

def load_dictionary():

    global COMMON_PASSWORDS
    global PASSWORD_RANKS

    path = Path(DICTIONARY_FILE)

    if not path.exists():

        print(
            "\n[!] Password dictionary not found."
        )

        print(
            "[!] Dictionary attack detection disabled."
        )

        return

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for rank, password in enumerate(
                file,
                start=1
            ):

                password = password.strip().lower()

                if password:

                    COMMON_PASSWORDS.add(password)

                    PASSWORD_RANKS[password] = rank

        print(
            f"\n[+] Loaded "
            f"{len(COMMON_PASSWORDS):,} "
            f"common passwords."
        )

    except Exception as error:

        print(
            f"[!] Failed to load dictionary: {error}"
        )

# ======================================================
# PASSWORD REUSE DETECTION
# ======================================================

def check_password_reuse(password):

    stored_hashes = get_all_password_hashes()

    for old_hash in stored_hashes:

        try:

            if ph.verify(old_hash, password):
                return True

        except VerifyMismatchError:
            continue

    save_password_hash(
        ph.hash(password)
    )

    return False

# ======================================================
# PASSWORD ENTROPY
# ======================================================

def calculate_entropy(password):

    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26

    if any(c.isupper() for c in password):
        charset_size += 26

    if any(c.isdigit() for c in password):
        charset_size += 10

    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    if charset_size == 0:
        return 0

    entropy = (
        len(password)
        * math.log2(charset_size)
    )

    return round(entropy, 2)

# ======================================================
# PASSWORD GENERATOR
# ======================================================

def generate_password(length=16):

    characters = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*"
    )

    while True:

        password = "".join(
            random.choice(characters)
            for _ in range(length)
        )

        if (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(
                c in "!@#$%^&*"
                for c in password
            )
        ):
            return password

# ======================================================
# PASSWORD ANALYSIS
# ======================================================

def analyze_password(password):

    score = 0
    feedback = []

    # Length

    if len(password) >= 16:
        score += 30

    elif len(password) >= 12:
        score += 25

    elif len(password) >= 8:
        score += 15

    else:
        feedback.append(
            "Password should be at least 8 characters."
        )

    # Uppercase

    if any(c.isupper() for c in password):
        score += 15
    else:
        feedback.append(
            "Add an uppercase letter."
        )

    # Lowercase

    if any(c.islower() for c in password):
        score += 15
    else:
        feedback.append(
            "Add a lowercase letter."
        )

    # Number

    if any(c.isdigit() for c in password):
        score += 15
    else:
        feedback.append(
            "Add a number."
        )

    # Special Character

    if re.search(
        r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>/?]',
        password
    ):
        score += 15
    else:
        feedback.append(
            "Add a special character."
        )

    # Entropy

    entropy = calculate_entropy(password)

    if entropy >= 80:
        score += 10

    elif entropy >= 60:
        score += 5

    # Dictionary Detection

    rank = None

    if password.lower() in COMMON_PASSWORDS:

        rank = PASSWORD_RANKS.get(
            password.lower()
        )

        score -= 40

        feedback.append(
            "Password appears in a common-password dictionary."
        )

        if rank:

            feedback.append(
                f"Dictionary rank: #{rank:,}"
            )

    score = max(0, min(score, 100))

    if score >= 80:
        strength = "STRONG"

    elif score >= 50:
        strength = "MEDIUM"

    else:
        strength = "WEAK"

    return (
        strength,
        score,
        entropy,
        rank,
        feedback
    )

# ======================================================
# MAIN APPLICATION
# ======================================================

def password_analyzer():

    print("\n" + "=" * 60)

    print(
        "PASSWORD STRENGTH ANALYZER"
    )

    print(
        "Argon2 + SQLite + Entropy + Dictionary Detection"
    )

    print("=" * 60)

    while True:

        password = input(
            "\nEnter password "
            "(or type 'exit'): "
        )

        if password.lower() == "exit":

            print(
                "\nThank you for using the tool."
            )

            break

        if check_password_reuse(password):

            print(
                "\n[WARNING] Password reuse detected!"
            )

            continue

        (
            strength,
            score,
            entropy,
            rank,
            feedback
        ) = analyze_password(password)

        print("\n" + "-" * 50)

        print(
            f"Strength : {strength}"
        )

        print(
            f"Score    : {score}/100"
        )

        print(
            f"Entropy  : {entropy} bits"
        )

        if rank:

            print(
                f"Rank     : #{rank:,}"
            )

        if feedback:

            print("\nRecommendations:")

            for item in feedback:

                print(
                    f"• {item}"
                )

        if strength != "STRONG":

            print(
                "\nSuggested Strong Passwords:"
            )

            for i in range(3):

                print(
                    f"{i+1}. "
                    f"{generate_password()}"
                )

        print("-" * 50)

# ======================================================
# ENTRY POINT
# ======================================================

if __name__ == "__main__":

    initialize_database()

    load_dictionary()

    password_analyzer()