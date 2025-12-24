import os
import stripe
from flask import Blueprint, request, jsonify, redirect, url_for
from datetime import datetime
from helpers import get_db, current_user

billing = Blueprint("billing", __name__)
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

PRICE_ID = os.environ["STRIPE_PRICE_ID_PRO_MONTHLY"]
BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")

@billing.post("/billing/checkout")
def billing_checkout():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.referrer or url_for("labs_pro_page")))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, stripe_customer_id FROM users WHERE id=?", (user["id"],))
    row = cur.fetchone()
    if not row:
        return "User not found", 404

    user_id, email, stripe_customer_id = row

    if not stripe_customer_id:
        customer = stripe.Customer.create(email=email, metadata={"user_id": str(user_id)})
        stripe_customer_id = customer["id"]
        cur.execute("UPDATE users SET stripe_customer_id=? WHERE id=?", (stripe_customer_id, user_id))
        conn.commit()

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

@billing.get("/billing/success")
def billing_success():
    return redirect(url_for("labs_pro_page", upgraded="1"))

@billing.post("/stripe/webhook")
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, os.environ["STRIPE_WEBHOOK_SECRET"])
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    etype = event["type"]
    obj = event["data"]["object"]

    conn = get_db()
    cur = conn.cursor()

    if etype == "checkout.session.completed" and obj.get("mode") == "subscription":
        stripe_customer_id = obj.get("customer")
        cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE users SET is_pro=1, pro_since=? WHERE id=?",
                        (datetime.utcnow().isoformat(), row[0]))
            conn.commit()

    if etype in ("customer.subscription.deleted", "customer.subscription.updated"):
        stripe_customer_id = obj.get("customer")
        status = obj.get("status")
        cur.execute("SELECT id FROM users WHERE stripe_customer_id=?", (stripe_customer_id,))
        row = cur.fetchone()
        if row:
            is_pro = 1 if status in ("active", "trialing") else 0
            cur.execute("UPDATE users SET is_pro=? WHERE id=?", (is_pro, row[0]))
            conn.commit()

    return jsonify({"ok": True})
@billing.post("/billing/portal")
def portal():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.referrer or url_for("labs_pro_page")))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT stripe_customer_id FROM users WHERE id=?", (user["id"],))
    row = cur.fetchone()
    if not row or not row[0]:
        return redirect(url_for("labs_pro_page"))

    portal_session = stripe.billing_portal.Session.create(
        customer=row[0],
        return_url=f"{BASE_URL}{url_for('labs_pro_page')}"
    )
    return redirect(portal_session.url, code=303)
