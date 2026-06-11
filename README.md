# 🔐 Password Strength Analyzer

A Python-based Password Strength Analyzer designed to evaluate password security using modern cybersecurity practices.

The application analyzes password complexity, entropy, uniqueness, and reuse while demonstrating fundamental authentication and cryptography concepts. It also uses Argon2 password hashing and SQLite database storage to securely manage password history.

---

## 📌 Features

### Password Complexity Analysis

* Minimum password length validation
* Uppercase letter detection
* Lowercase letter detection
* Numeric character detection
* Special character detection

### Password Entropy Calculation

* Calculates password entropy (in bits)
* Estimates password randomness and strength
* Provides additional scoring for high-entropy passwords

### Common Password Detection

* Supports the Xato Top Password Dataset
* Detects passwords vulnerable to dictionary attacks
* Displays password ranking if found in the dataset

### Password Reuse Prevention

* Uses Argon2 password hashing
* Stores password hashes in SQLite
* Detects previously used passwords

### Secure Password Suggestions

* Generates strong random passwords
* Includes uppercase, lowercase, numbers, and symbols

### Password Strength Scoring

* Assigns a score between 0–100
* Classifies passwords as:

  * Weak
  * Medium
  * Strong

---

## 🛡️ Security Concepts Demonstrated

This project demonstrates several cybersecurity concepts:

* Password Security
* Authentication
* Password Entropy
* Dictionary Attack Detection
* Password Reuse Prevention
* Cryptographic Hashing
* Argon2 Password Hashing
* Salting
* Secure Credential Storage
* SQLite Database Management

---

## ⚙️ Technologies Used

* Python 3.x
* Argon2
* SQLite3
* Regular Expressions (Regex)
* Xato Password Dataset
* Git & GitHub

---

## 📂 Project Structure

```text
password-strength-analyzer/
│
├── password_analyzer.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── password_history.db          (generated automatically)
│
└── xato-net-10-million-passwords-1000000.txt
   (optional)
```

---

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-analyzer.git

cd password-strength-analyzer
```

### Create Virtual Environment

#### Windows

```bash
python -m venv .venv
```

Activate:

```bash
.venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
```

Activate:

```bash
source .venv/bin/activate
```

---

### Install Dependencies

```bash
pip install -r requirements.txt

- argon2-cffi (password hashing)

All other modules used by the project are part of Python's standard library.
```

---

## 📖 Optional: Password Dictionary Setup

This project supports common-password detection using the Xato Password Dataset.

Download the dataset from:

https://github.com/danielmiessler/SecLists

Place the file below in the project root directory:

```text
xato-net-10-million-passwords-1000000.txt
```

If the file is not present, the application will still work normally, but dictionary-based password detection will be disabled.

---

## ▶️ Running the Application

```bash
python password_analyzer.py
```

---

## 🧪 Example Output

```text
============================================================
PASSWORD STRENGTH ANALYZER
Argon2 + SQLite + Entropy + Dictionary Detection
============================================================

Enter password (or type 'exit'): Password123

--------------------------------------------------
Strength : WEAK
Score    : 25/100
Entropy  : 42.3 bits

Recommendations:
• Add a special character.
• Password appears in a common-password dictionary.

Suggested Strong Passwords:
1. P@7mX2!qL9#vRt
2. H$4kJ8@zW2!nMp
3. T#9aQ7&vB5!xLs
--------------------------------------------------
```

---

## 🔒 Password Storage

Passwords are **never stored in plaintext**.

The application uses:

* Argon2 password hashing
* Automatic salting
* SQLite database storage

Only password hashes are stored for reuse detection.

---

## 🎯 Learning Outcomes

Through this project, users can learn:

* Password security best practices
* Password complexity requirements
* Entropy and randomness
* Dictionary attacks
* Secure password storage
* Argon2 hashing
* Database integration with Python
* Authentication fundamentals

---

## 🔮 Future Enhancements

Possible future improvements:

* GUI using Tkinter or PyQt
* Password breach checking using Have I Been Pwned API
* Multi-user support
* Password strength visualization graphs
* Export security reports
* User authentication system

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

Mohamed Asif

Cybersecurity Enthusiast | SOC | Cloud Security | Application Security
