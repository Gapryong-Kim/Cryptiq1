import os
import sqlite3
from flask import session, request

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cryptiq.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def current_user():
    """
    Returns the logged-in user row as a dict, or None.
    NOTE: uses session["user_id"] set by your login flow.
    """
    if "user_id" not in session:
        return None

    conn = get_db()
    cur = conn.execute(
        """
        SELECT
            id, username, email, is_admin, banned,
            labs_info_seen, is_pro, stripe_customer_id,
            pro_current_period_end, pro_cancel_at_period_end
        FROM users
        WHERE id=?
        """,
        (session["user_id"],),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ======================================================
# Currency helpers (Hybrid Pricing)
# ======================================================

SUPPORTED_CURRENCIES = {
    "GBP": "£",
    "EUR": "€",
    "USD": "$",
}

# Optional: map country -> currency (you can expand later)
_COUNTRY_TO_CURRENCY = {
    # GBP
    "GB": "GBP",
    "IE": "GBP",
    # EUR (common)
    "DE": "EUR",
    "FR": "EUR",
    "ES": "EUR",
    "IT": "EUR",
    "NL": "EUR",
    # USD
    "US": "USD",
    "CA": "USD",
}


def set_currency(code: str):
    code = (code or "").upper().strip()
    if code in SUPPORTED_CURRENCIES:
        session["currency"] = code


def detect_currency() -> str:
    """
    Best-effort currency detection:
    1) Reverse-proxy headers (Cloudflare, etc.)
    2) Accept-Language
    Defaults to GBP.
    """
    # Reverse proxy / CDN headers (add yours if you have them)
    for h in ("CF-IPCountry", "X-Country-Code", "X-Geo-Country"):
        c = request.headers.get(h)
        if c:
            c = c.upper().strip()
            if c in _COUNTRY_TO_CURRENCY:
                return _COUNTRY_TO_CURRENCY[c]

    # Accept-Language fallback (coarse, but decent)
    lang = (request.accept_languages.best or "").lower()
    if lang.startswith("en-gb"):
        return "GBP"
    if lang.startswith(("de", "fr", "es", "it", "nl")):
        return "EUR"
    if lang.startswith("en-us"):
        return "USD"

    return "GBP"


def get_currency() -> str:
    # User preference wins
    cur = (session.get("currency") or "").upper().strip()
    if cur in SUPPORTED_CURRENCIES:
        return cur
    return detect_currency()


def get_currency_symbol() -> str:
    return SUPPORTED_CURRENCIES.get(get_currency(), "£")



def get_labs_pro_price_id():
    cur = get_currency()

    if cur == "EUR":
        return os.environ["price_EUR_ID"]
    if cur == "USD":
        return os.environ["price_USD_ID"]

    # default GBP
    return os.environ["price_GBP_ID"]