# Fixture for the code review lab (parsed only).
import os

DEBUG = os.environ.get("APP_DEBUG", "0") == "1"
ALLOWED_HOSTS = ["shop.example"]
SECRET_KEY = os.environ["APP_SECRET_KEY"]
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CORS_ALLOWED_ORIGINS = ["https://shop.example"]
