"""Server settings. DELIBERATELY VULNERABLE: hardcoded secrets and a wide network bind.

Every key below is FAKE. None of them is a real credential.
"""

HOST = "0.0.0.0"
PORT = 8808
NOTES_DIR = "notes"

API_KEY = "sk-FAKE0123456789abcdefABCDEF0123456789abcd"  # FAKE
AWS_ACCESS_KEY_ID = "AKIAFAKEEXAMPLEKEY12"  # FAKE
GITHUB_TOKEN = "ghp_FAKE0123456789abcdefghijklmnopqrstuv"  # FAKE
DB_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEYFAKE"  # FAKE high-entropy value
