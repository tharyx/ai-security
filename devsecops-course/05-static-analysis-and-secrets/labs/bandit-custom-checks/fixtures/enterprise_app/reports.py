"""Reporting and sync jobs (fixture, parsed only)."""
import logging

from corp_http import client as http

logger = logging.getLogger(__name__)


def sync_customer(customer):  # expect: secret-log
    logger.info("syncing customer %s with token %s", customer.id, customer.api_token)
    return http.post("https://crm.example/api/customers", json=customer.as_dict(), timeout=5)


def password_reset_requested(user):
    logger.info("password reset requested for user %s", user.id)


def refresh_cache(session):
    logger.debug("cache holds %d entries, token_count=%d", len(session.cache), session.token_count)


def audit_login(form):  # expect: secret-log
    logger.warning("failed login: %s", form["password"])


def masked(user):
    logger.info("api key in use: %s", mask(user.api_key))


def fetch_rates():  # expect: timeout
    return http.get("https://rates.example/v1")


def fetch_rates_ok():
    return http.get("https://rates.example/v1", timeout=3)
