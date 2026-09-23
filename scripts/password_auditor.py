import secrets
import string
import math
import hashlib
import requests
import argparse

def generate_password(length=16):
    """Generates a cryptographically secure password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password, alphabet

def calculate_entropy(password, alphabet):
    """Calculates the mathematical entropy of the password."""
    pool_size = len(alphabet)
    password_length = len(password)
    # Entropy formula: E = L * log2(N)
    entropy = password_length * math.log2(pool_size)
    return entropy

def check_pwned_api(password):
    """
    Checks if the password has been exposed in data breaches using HIBP API.
    Implements k-Anonymity by only sending the first 5 characters of the SHA-1 hash.
    """
    # 1. Generate SHA-1 hash of the password
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 2. Split hash into prefix (first 5 chars) and suffix (the rest)
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # 3. Query the API with ONLY the prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        'User-Agent': 'Advanced-Password-Auditor-Lab'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return f"Error connecting to API: {response.status_code}", "Unknown"
        
        # 4. Check if our suffix is in the response list
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True, int(count) # Password was found 'count' times
        return False, 0
    except requests.exceptions.RequestException as e:
        return f"Connection error: {e}", "Unknown"

def evaluate_strength(entropy, is_pwned):
    """Evaluates overall security posture of the password."""
    if is_pwned:
        return "CRITICAL RISK: Compromised"
    if entropy < 50:
        return "WEAK: Susceptible to brute force"
    elif entropy < 80:
        return "MODERATE: Meets baseline security"
    else:
        return "STRONG: High resistance to cracking"

def main():
    parser = argparse.ArgumentParser(description="Advanced Password Generator & Entropy Auditor")
    parser.add_argument("-l", "--length", type=int, default=16, help="Length of the generated password (default: 16)")
    parser.add_argument("-c", "--custom", type=str, help="Audit a custom password instead of generating one")
    args = parser.parse_args()

    print("=" * 60)
    print(" 🔐 ADVANCED PASSWORD AUDITOR & GENERATOR")
    print("=" * 60)

    # Use custom password or generate a new one
    if args.custom:
        password = args.custom
        alphabet = string.ascii_letters + string.digits + string.punctuation
        print(f"\n[*] Auditing custom user-provided password...")
    else:
        password, alphabet = generate_password(args.length)
        print(f"\n[*] Generating secure {args.length}-character password...")
        print(f"    -> [ {password} ]")

    # 1. Entropy Analysis
    entropy = calculate_entropy(password, alphabet)
    print(f"\n[+] Entropy Analysis:")
    print(f"    - Base Pool Size : {len(alphabet)} characters")
    print(f"    - Entropy Score  : {entropy:.2f} bits")

    # 2. Vulnerability Check (Have I Been Pwned)
    print(f"\n[+] Vulnerability Check (HIBP API via k-Anonymity):")
    print("    - Hashing password (SHA-1)...")
    is_pwned, count = check_pwned_api(password)
    
    if is_pwned is True:
        print(f"    - ❌ BREACH DETECTED: Found in {count:,} known data breaches!")
    elif is_pwned is False:
        print("    - ✅ SECURE: Not found in any known data breaches.")
    else:
        print(f"    - ⚠️ {is_pwned}")

    # 3. Final Verdict
    strength = evaluate_strength(entropy, is_pwned)
    print(f"\n[*] Final Security Verdict: {strength}")
    print("=" * 60)

if __name__ == "__main__":
    main()