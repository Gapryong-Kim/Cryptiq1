import os
import stripe
from flask import Blueprint, request, jsonify, redirect, url_for
from datetime import datetime
from helpers import get_db, current_user

billing = Blueprint("billing", __name__)

# Stripe config
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
PRICE_ID = os.environ.get("STRIPE_PRICE_ID_PRO_MONTHLY", "")
BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")


# ----------------------------
# Helpers
# ----------------------------
def _is_no_such_customer_error(e: Exception) -> bool:
    """
    Stripe raises InvalidRequestError for:
      "No such customer: cus_..."
    But depending on stripe version / language server, importing stripe.error may be flaky.
    So we detect by class name + message.
    """
    cls = e.__class__.__name__
    msg = str(e).lower()
    if cls == "InvalidRequestError" and ("no such customer" in msg or "customer" in msg):
        return True
    return False


def ensure_stripe_customer(conn, user_id: int, email: str, stripe_customer_id: str | None) -> str:
    """
    Returns a valid Stripe customer id. If the stored one is missing or stale (deleted / wrong mode / wrong account),
    it creates a new customer and updates the DB.
    """
    cur = conn.cursor()

    if stripe_customer_id:
        try:
            stripe.Customer.retrieve(stripe_customer_id)
            return stripe_customer_id
        except Exception as e:
            # If the stored customer id doesn't exist in this Stripe account/environment, recreate.
            if not _is_no_such_customer_error(e):
                raise
            stripe_customer_id = None

    customer = stripe.Customer.create(email=email, metadata={"user_id": str(user_id)})
    stripe_customer_id = customer["id"]
    cur.execute("UPDATE users SET stripe_customer_id=? WHERE id=?", (stripe_customer_id, user_id))
    conn.commit()
    return stripe_customer_id


# ----------------------------
# Checkout (Start subscription)
# ----------------------------
@billing.post("/billing/checkout")
def billing_checkout():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.referrer or url_for("labs_pro_page")))

    if not stripe.api_key:
        return "Stripe is not configured (missing STRIPE_SECRET_KEY)", 500
    if not PRICE_ID:
        return "Stripe is not configured (missing STRIPE_PRICE_ID_PRO_MONTHLY)", 500

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, stripe_customer_id FROM users WHERE id=?", (user["id"],))
        row = cur.fetchone()
        if not row:
            return "User not found", 404

        user_id, email, stripe_customer_id = row

        # Ensure the customer exists in the current Stripe environment
        stripe_customer_id = ensure_stripe_customer(conn, user_id, email, stripe_customer_id)

        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=stripe_customer_id,
            line_items=[{"price": PRICE_ID, "quantity": 1}],
            allow_promotion_codes=True,
            success_url=f"{BASE_URL}{url_for('billing.billing_success')}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}{url_for('labs_pro_page')}",
            metadata={"user_id": str(user_id)},
        )
        return redirect(session.url, code=303)
    finally:
        conn.close()


@billing.get("/billing/success")
def billing_success():
    return redirect(url_for("labs_pro_page", upgraded="1"))


# ----------------------------
# Stripe Webhook
# ----------------------------
@billing.post("/stripe/webhook")
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            os.environ.get("STRIPE_WEBHOOK_SECRET", "")
        )
    except Exception as e:
        # SignatureVerificationError is the common one, but avoid stripe.error import issues.
        if e.__class__.__name__ == "SignatureVerificationError":
            return "Invalid signature", 400
        return "Webhook error", 400

    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}

    conn = get_db()
    try:
        cur = conn.cursor()

        # Checkout completed -> set pro
        if etype == "checkout.session.completed" and obj.get("mode") == "subscription":
            stripe_customer_id = obj.get("customer")
            if stripe_customer_id:
                cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE users SET is_pro=1, pro_since=? WHERE id=?",
                        (datetime.utcnow().isoformat(), row[0])
                    )
                    conn.commit()

        # Subscription updated/deleted -> update pro
        if etype in ("customer.subscription.deleted", "customer.subscription.updated"):
            stripe_customer_id = obj.get("customer")
            status = obj.get("status")
            if stripe_customer_id:
                cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
                row = cur.fetchone()
                if row:
                    is_pro = 1 if status in ("active", "trialing") else 0
                    cur.execute("UPDATE users SET is_pro=? WHERE id=?", (is_pro, row[0]))
                    conn.commit()

        return jsonify({"ok": True})
    finally:
        conn.close()


# ----------------------------
# Billing portal
# ----------------------------
@billing.post("/billing/portal")
def portal():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.referrer or url_for("labs_pro_page")))

    if not stripe.api_key:
        return "Stripe is not configured (missing STRIPE_SECRET_KEY)", 500

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, stripe_customer_id FROM users WHERE id=?", (user["id"],))
        row = cur.fetchone()
        if not row:
            return redirect(url_for("labs_pro_page"))

        user_id, email, stripe_customer_id = row

        # Ensure the customer exists in the current Stripe environment
        stripe_customer_id = ensure_stripe_customer(conn, user_id, email, stripe_customer_id)

        portal_session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{BASE_URL}{url_for('labs_pro_page')}"
        )
        return redirect(portal_session.url, code=303)
    finally:
        conn.close()
