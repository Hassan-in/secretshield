"""
crypto_checks.py
Static signatures for weak / deprecated cryptographic practices across
Python, JavaScript/TypeScript, Java, Go, and C#.
"""

import re

CRYPTO_PATTERNS = [
    (
        "weak_hash_md5",
        "MD5 Used for Hashing",
        re.compile(r"(?i)\b(hashlib\.md5|MD5\(|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|CryptoJS\.MD5|md5\()"),
        "HIGH",
        "MD5 is cryptographically broken; unsuitable for passwords, signatures, or integrity checks.",
    ),
    (
        "weak_hash_sha1",
        "SHA-1 Used for Hashing",
        re.compile(r"(?i)\b(hashlib\.sha1|SHA1\(|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|CryptoJS\.SHA1)"),
        "MEDIUM",
        "SHA-1 has known collision attacks; avoid for security-sensitive hashing or signatures.",
    ),
    (
        "weak_cipher_des",
        "DES / 3DES Cipher Usage",
        re.compile(r"(?i)\b(DES|TripleDES|3DES|DESede)\b"),
        "HIGH",
        "DES/3DES use small key sizes / block sizes and are considered insecure.",
    ),
    (
        "weak_cipher_rc4",
        "RC4 Stream Cipher Usage",
        re.compile(r"(?i)\bRC4\b"),
        "HIGH",
        "RC4 has documented biases and should not be used.",
    ),
    (
        "ecb_mode",
        "AES/DES in ECB Mode",
        re.compile(r"(?i)(AES|DES).{0,20}/ECB/|Cipher\.getInstance\(\s*[\"'][^\"']*ECB[^\"']*[\"']|MODE_ECB"),
        "HIGH",
        "ECB mode leaks plaintext patterns; use GCM or CBC with a random IV instead.",
    ),
    (
        "hardcoded_iv",
        "Hardcoded / Static IV or Nonce",
        re.compile(r"(?i)\b(iv|nonce)\s*=\s*[\"'][0-9a-fA-F]{8,}[\"']|\b(iv|nonce)\s*=\s*b[\"'][^\"']+[\"']"),
        "MEDIUM",
        "Reusing a static IV/nonce with block or stream ciphers undermines confidentiality.",
    ),
    (
        "hardcoded_crypto_key",
        "Hardcoded Symmetric Encryption Key",
        re.compile(r"(?i)\b(secret[_-]?key|encryption[_-]?key|cipher[_-]?key)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{8,}[\"']"),
        "CRITICAL",
        "Symmetric key embedded in source code; anyone with source access can decrypt data.",
    ),
    (
        "insecure_random",
        "Insecure PRNG for Security Purposes",
        re.compile(r"(?i)\b(Math\.random\(\)|random\.random\(|new Random\(\)|java\.util\.Random)\b"),
        "MEDIUM",
        "Non-cryptographic PRNGs are predictable; use os.urandom/secrets, crypto.randomBytes or SecureRandom.",
    ),
    (
        "weak_key_size_rsa",
        "Weak RSA Key Size",
        re.compile(r"(?i)(RSA\.generate\(\s*(512|768|1024)\s*\)|keysize\s*[:=]\s*(512|768|1024)\b|generateKeyPair\(\s*[\"']RSA[\"']\s*,\s*(512|768|1024))"),
        "HIGH",
        "RSA keys below 2048 bits are considered breakable with modern resources.",
    ),
    (
        "ssl_verify_disabled",
        "TLS/SSL Certificate Verification Disabled",
        re.compile(r"(?i)(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*false|CURLOPT_SSL_VERIFYPEER.{0,10}0|InsecureSkipVerify\s*:\s*true|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER)"),
        "HIGH",
        "Disabling certificate verification exposes connections to man-in-the-middle attacks.",
    ),
    (
        "weak_password_hash",
        "Fast Hash Used Instead of Password KDF",
        re.compile(r"(?i)(hashlib\.sha256\([^)]*password|md5\([^)]*password|sha1\([^)]*password)"),
        "HIGH",
        "Passwords should be hashed with bcrypt/scrypt/Argon2/PBKDF2, not a fast general-purpose hash.",
    ),
    (
        "jwt_none_alg",
        "JWT 'none' Algorithm Accepted",
        re.compile(r"(?i)algorithms\s*=\s*\[?\s*[\"']none[\"']|alg[\"']?\s*:\s*[\"']none[\"']"),
        "CRITICAL",
        "Accepting the 'none' JWT algorithm lets attackers forge unsigned tokens.",
    ),
    (
        "weak_key_derivation_iterations",
        "Low Iteration Count in Key Derivation",
        re.compile(r"(?i)PBKDF2.{0,40}(iterations\s*[:=]\s*(?:[1-9][0-9]{0,2})\b)"),
        "MEDIUM",
        "PBKDF2 iteration counts under ~1000 are too low for modern hardware; use 100k+ or Argon2/bcrypt/scrypt.",
    ),
    (
        "custom_crypto_impl",
        "Possible Custom/Home-grown Cryptography",
        re.compile(r"(?i)\bdef\s+(encrypt|decrypt)\w*\s*\(.*\):\s*$"),
        "LOW",
        "Custom encrypt/decrypt function detected — verify it wraps a vetted library rather than inventing a cipher.",
    ),
]
