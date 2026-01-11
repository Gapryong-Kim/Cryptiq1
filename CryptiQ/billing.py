import os
import re
from datetime import datetime

import stripe
from flask import Blueprint, request, jsonify, redirect, url_for, session, abort

from helpers import (
    get_db,
    current_user,
    get_labs_pro_price_id,
    get_currency,
)

from werkzeug.security import generate_password_hash

billing = Blueprint("billing", __name__)

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")


# ======================================================
# Helpers
# ======================================================
def _iso_now():
    return datetime.utcnow().isoformat()


def _safe_username_base(email: str) -> str:
    base = (email or "").split("@", 1)[0].strip().lower()
    base = re.sub(r"[^a-z0-9_]+", "_", base)
    base = re.sub(r"_+", "_", base).strip("_")
    if not base:
        base = "cipher"
    return base[:20]


def _unique_username(conn, base: str) -> str:
    base = (base or "cipher").strip().lower()
    base = re.sub(r"[^a-z0-9_]+", "_", base)
    base = re.sub(r"_+", "_", base).strip("_") or "cipher"
    base = base[:20]

    # try base, then base_2...base_9999
    row = conn.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (base,)).fetchone()
    if not row:
        return base

    for i in range(2, 10000):
        cand = f"{base}_{i}"
        row = conn.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (cand,)).fetchone()
        if not row:
            return cand

    # last resort
    return f"{base}_{int(datetime.utcnow().timestamp())}"


def _get_or_create_stripe_customer(conn, user_id: int, email: str):
    row = conn.execute(
        "SELECT stripe_customer_id FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    stripe_customer_id = (row["stripe_customer_id"] if row else None)

    if stripe_customer_id:
        return stripe_customer_id

    customer = stripe.Customer.create(
        email=email,
        metadata={"user_id": str(user_id), "currency": get_currency()}
    )
    stripe_customer_id = customer["id"]
    conn.execute(
        "UPDATE users SET stripe_customer_id=? WHERE id=?",
        (stripe_customer_id, user_id)
    )
    conn.commit()
    return stripe_customer_id


# ======================================================
# Checkout
# ======================================================
@billing.post("/billing/checkout")
def billing_checkout():
    user = current_user()

    # Logged-in users: normal upgrade flow
    if user:
        conn = get_db()
        row = conn.execute(
            "SELECT id, email FROM users WHERE id=?",
            (user["id"],)
        ).fetchone()

        if not row:
            conn.close()
            return "User not found", 404

        user_id = row["id"]
        email = row["email"] or ""

        stripe_customer_id = _get_or_create_stripe_customer(conn, user_id, email)
        conn.close()

        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            customer=stripe_customer_id,
            line_items=[{"price": get_labs_pro_price_id(), "quantity": 1}],
            allow_promotion_codes=True,
            success_url=f"{BASE_URL}{url_for('billing.billing_success')}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}{url_for('labs_pro_page')}",
            metadata={"user_id": str(user_id), "currency": get_currency()},
        )
        return redirect(checkout_session.url, code=303)

    # Guest users: collect email, create checkout, and auto-create the account in webhook
    email = (request.form.get("email") or "").strip().lower()
    if not email or "@" not in email:
        # keep it simple (labs_pro page can display error from query param)
        return redirect(url_for("labs_pro_page", checkout_error="email"))

    checkout_session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": get_labs_pro_price_id(), "quantity": 1}],
        allow_promotion_codes=True,
        success_url=f"{BASE_URL}{url_for('billing.billing_success')}?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{BASE_URL}{url_for('labs_pro_page')}",
        customer_email=email,
        metadata={
            "pending_email": email,
            "currency": get_currency(),
        },
    )

    return redirect(checkout_session.url, code=303)


@billing.get("/billing/success")
def billing_success():
    """After Stripe success, automatically claim + log the user in."""
    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return redirect(url_for("labs_pro_page", upgraded="1"))
    return redirect(url_for("billing.billing_claim", session_id=session_id))



# ======================================================
# Stripe Webhook
# ======================================================
# ======================================================
# Claim (auto-login after guest checkout)
# ======================================================
@billing.get("/billing/claim")
def billing_claim():
    """
    Given a Stripe Checkout Session ID, ensure we have a local user for the
    purchase, attach the Stripe customer id, mark them Pro, then log them in.

    Works for both:
    - logged-in upgrades (already have session["user_id"])
    - guest checkout (email collected on Labs Pro page)
    """
    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        abort(400)

    # Retrieve Stripe Checkout Session and sanity-check
    cs = stripe.checkout.Session.retrieve(session_id)
    if getattr(cs, "status", None) != "complete":
        abort(400, description="Checkout not complete.")

    customer_id = getattr(cs, "customer", None)
    if not customer_id:
        abort(400, description="No Stripe customer on session.")

    # Prefer explicit email fields; Stripe can provide it in different places
    email = (
        (getattr(cs, "customer_email", None) or "")
        or ((getattr(cs, "customer_details", None) or {}).get("email") if isinstance(getattr(cs, "customer_details", None), dict) else "")
    )
    email = (email or "").strip().lower()

    conn = get_db()
    cur = conn.cursor()

    # 1) If already logged in, attach to current user
    user = current_user()
    if user:
        uid = int(user["id"])
        cur.execute(
            "UPDATE users SET stripe_customer_id=COALESCE(stripe_customer_id, ?), is_pro=1, pro_since=? WHERE id=?",
            (customer_id, _iso_now(), uid)
        )
        conn.commit()
        conn.close()
        session["user_id"] = uid  # keep session fresh
        return redirect(url_for("account"))

    # 2) Guest: find by stripe_customer_id first
    cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (customer_id,))
    row = cur.fetchone()
    uid = row[0] if row else None

    # 3) Else find by email
    if not uid and email:
        cur.execute("SELECT id FROM users WHERE lower(email)=lower(?)", (email,))
        row = cur.fetchone()
        uid = row[0] if row else None

    # 4) Else create user (covers webhook delays)
    if not uid:
        if not email:
            conn.close()
            abort(400, description="No email on checkout session.")

        username_base = _safe_username_base(email)
        username = _unique_username(conn, username_base)

        # placeholder password hash (user sets real password in /account)
        placeholder = generate_password_hash(os.urandom(24).hex())

        cur.execute(
            """
            INSERT INTO users
              (username, email, password_hash, is_admin, created_at,
               is_pro, pro_since, stripe_customer_id, needs_password, needs_username)
            VALUES
              (?, ?, ?, 0, ?, 1, ?, ?, 1, 1)
            """,
            (username, email, placeholder, _iso_now(), _iso_now(), customer_id)
        )
        uid = cur.lastrowid

    # Ensure pro + customer attached (idempotent)
    cur.execute(
        "UPDATE users SET is_pro=1, pro_since=COALESCE(pro_since, ?), stripe_customer_id=COALESCE(stripe_customer_id, ?) WHERE id=?",
        (_iso_now(), customer_id, uid)
    )
    conn.commit()
    conn.close()

    # ✅ Auto-login
    session["user_id"] = int(uid)
    return redirect(url_for("account"))


@billing.post("/stripe/webhook")
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            os.environ["STRIPE_WEBHOOK_SECRET"]
        )
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    etype = event["type"]
    obj = event["data"]["object"]

    conn = get_db()
    cur = conn.cursor()

    # --------------------------------------------
    # Grant PRO + attach Stripe customer ID
    # --------------------------------------------
    if etype == "checkout.session.completed" and obj.get("mode") == "subscription":
        stripe_customer_id = obj.get("customer")
        md = obj.get("metadata") or {}
        user_id = md.get("user_id")
        email = (md.get("pending_email") or obj.get("customer_email") or (obj.get("customer_details") or {}).get("email") or "").strip().lower()

        # 1) If user_id provided (logged-in checkout)
        if user_id:
            cur.execute(
                "UPDATE users SET is_pro=1, pro_since=?, stripe_customer_id=? WHERE id=?",
                (_iso_now(), stripe_customer_id, int(user_id))
            )
            conn.commit()
            conn.close()
            return jsonify({"ok": True})

        # 2) Guest checkout: find or create user by email
        if email:
            cur.execute("SELECT id, stripe_customer_id FROM users WHERE lower(email)=lower(?)", (email,))
            row = cur.fetchone()

            if row:
                uid = row[0]
                existing_cust = row[1]
                cur.execute(
                    "UPDATE users SET is_pro=1, pro_since=?, stripe_customer_id=COALESCE(stripe_customer_id, ?) WHERE id=?",
                    (_iso_now(), stripe_customer_id, uid)
                )
                conn.commit()
            else:
                # Create a new account (needs username + password setup)
                username_base = _safe_username_base(email)
                username = _unique_username(conn, username_base)

                # random placeholder password hash (user will set a real one in /account)
                placeholder = generate_password_hash(os.urandom(24).hex())

                cur.execute(
                    """
                    INSERT INTO users (username, email, password_hash, is_admin, created_at, is_pro, pro_since, stripe_customer_id, needs_password, needs_username)
                    VALUES (?, ?, ?, 0, ?, 1, ?, ?, 1, 1)
                    """,
                    (username, email, placeholder, _iso_now(), _iso_now(), stripe_customer_id)
                )
                conn.commit()

    # --------------------------------------------
    # Re-enable PRO if Stripe recovers subscription
    # --------------------------------------------
    elif etype == "customer.subscription.updated":
        status = obj.get("status")
        stripe_customer_id = obj.get("customer")

        if status in ("active", "trialing"):
            cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE users SET is_pro=1 WHERE id=?", (row[0],))
                conn.commit()

    # --------------------------------------------
    # Remove PRO ONLY when subscription is deleted
    # --------------------------------------------
    elif etype == "customer.subscription.deleted":
        stripe_customer_id = obj.get("customer")

        cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE users SET is_pro=0 WHERE id=?", (row[0],))
            conn.commit()

    conn.close()
    return jsonify({"ok": True})


# ======================================================
# Billing Portal
# ======================================================
@billing.post("/billing/portal")
def portal():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.referrer or url_for("labs_pro_page")))

    conn = get_db()
    row = conn.execute(
        "SELECT id, email FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()

    if not row:
        conn.close()
        return redirect(url_for("labs_pro_page"))

    user_id = row["id"]
    email = row["email"] or ""

    stripe_customer_id = _get_or_create_stripe_customer(conn, user_id, email)
    conn.close()

    portal_session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id,
        return_url=f"{BASE_URL}{url_for('labs_pro_page')}"
    )

    return redirect(portal_session.url, code=303)
