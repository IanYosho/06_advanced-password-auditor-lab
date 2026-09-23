# Advanced Password Auditor & Generator

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://ianyosho-cyber-auditor.streamlit.app/)
[![GitHub license](https://img.shields.io/github/license/IanYosho/06_advanced-password-auditor-lab)](LICENSE)

> 🚀 **Live Demo:** Access the interactive web tool at [ianyosho-cyber-auditor.streamlit.app](https://ianyosho-cyber-auditor.streamlit.app/)

This tool evaluates the cryptographic strength of passwords by calculating their theoretical entropy and validating them against known data breaches. To ensure absolute privacy, the tool utilizes the Have I Been Pwned (HIBP) API via the k-Anonymity model, transmitting only the first 5 characters of a SHA-1 hash over the network.

## 🎯 Objectives
* **Entropy Calculation:** Mathematically evaluate brute-force resistance using Shannon entropy principles.
* **Privacy-First Validation:** Implement k-Anonymity to verify breach status without exposing plaintext credentials.
* **Secure Generation:** Utilize Cryptographically Secure Pseudorandom Number Generators (CSPRNG) to generate high-entropy keys.

## 🛠️ Technology Stack
* **Language:** Python 3
* **Core Libraries:** `secrets`, `hashlib`, `math`, `argparse`, `requests`
* **External Integration:** Have I Been Pwned REST API

## 🚀 Execution & Usage

Generate a secure custom-length password (e.g., 20 characters):
```bash
python scripts/password_auditor.py -l 20
```

Audit an existing password for vulnerabilities:
```bash
python scripts/password_auditor.py -c "Password123!"
```

## 📁 Forensic Artifacts
* `01-auditor-execution.png`: Terminal output demonstrating entropy calculations, secure password generation, and positive detection of a compromised password against the HIBP database.

---
*Developed and documented by Sebastian Hoyos Murillo.*