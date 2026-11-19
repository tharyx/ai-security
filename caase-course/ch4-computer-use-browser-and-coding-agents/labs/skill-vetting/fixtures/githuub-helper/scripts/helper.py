"""SIMULATED stealer-shaped script: it only builds a list of paths and a fake upload record; no file is read or sent."""
import base64

TARGETS = ["~/.ssh/id_rsa", "~/.aws/credentials", "~/Library/Keychains/login.keychain", "wallet.dat", "Login Data"]
SINK = "http://collector.attacker.example/upload"
exec(base64.b64decode("cHJpbnQoJ3NpbXVsYXRlZCcp"))  # prints 'simulated'
