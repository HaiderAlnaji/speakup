"""Tests for real payments (Paddle webhook). Run: python billing_test.py

The security property under test: is_premium can ONLY ever be granted by a
correctly-signed webhook from Paddle — never by the browser, never by a
plain API call, never by a forged/tampered request. This file tries hard
to break that invariant and confirms every attempt fails.
"""
import os, hmac, hashlib, json, time
if os.path.exists("app.db"):
    os.remove("app.db")

# Configure Paddle as if this were production, BEFORE importing main (config
# is read once at import time).
os.environ["PADDLE_API_KEY"] = "test_api_key"
os.environ["PADDLE_WEBHOOK_SECRET"] = "whsec_test_secret_12345"
os.environ["PADDLE_CLIENT_TOKEN"] = "live_test_client_token"
os.environ["PADDLE_PRICE_ID"] = "pri_test_pro_monthly"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

WEBHOOK_SECRET = "whsec_test_secret_12345"

def sign(body: bytes, secret: str = WEBHOOK_SECRET, ts: str = None) -> str:
    """Build a genuinely valid Paddle-style signature header for a body."""
    ts = ts or str(int(time.time()))
    signed_payload = f"{ts}:".encode() + body
    h1 = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"ts={ts};h1={h1}"

check("Paddle detected as configured", main.PADDLE_CONFIGURED is True)

# ---- setup a normal user ----
r = c.post("/api/register", json={"email": "buyer@test.com", "password": "strongpass123"})
buyer_id = r.json()["user"]
auth = {"Authorization": "Bearer " + r.json()["token"]}
with Session(main.engine) as s:
    buyer = s.exec(select(main.User).where(main.User.email == "buyer@test.com")).first()
    buyer_id = buyer.id
check("new user starts on free plan", r.json()["user"]["is_premium"] is False)

# ---- demo /api/upgrade is DISABLED now that Paddle is configured ----
r = c.post("/api/upgrade", headers=auth)
check("demo /api/upgrade shortcut is closed once Paddle is configured (403)",
      r.status_code == 403)
r = c.get("/api/me", headers=auth)
check("user is still free after the blocked demo attempt", r.json()["is_premium"] is False)

# ---- billing config never leaks secrets ----
r = c.get("/api/billing/config", headers=auth)
body = r.json()
check("billing config exposes only the public client token", body["client_token"] == "live_test_client_token")
check("billing config never includes the API key", "test_api_key" not in json.dumps(body))
check("billing config never includes the webhook secret", "whsec_test_secret_12345" not in json.dumps(body))
check("billing config reports configured=true", body["configured"] is True)

# ---- THE CORE SECURITY TEST: a forged webhook must be rejected ----
fake_event = json.dumps({
    "event_type": "subscription.created",
    "data": {"id": "sub_fake", "customer_id": "ctm_fake",
             "custom_data": {"user_id": str(buyer_id)}},
}).encode()

# 1. No signature header at all
r = c.post("/api/billing/webhook", content=fake_event,
           headers={"content-type": "application/json"})
check("webhook with NO signature is rejected (400)", r.status_code == 400)

# 2. Completely made-up signature
r = c.post("/api/billing/webhook", content=fake_event,
           headers={"content-type": "application/json", "paddle-signature": "ts=123;h1=deadbeef"})
check("webhook with a fabricated signature is rejected (400)", r.status_code == 400)

# 3. Correct format, wrong secret (attacker doesn't know the real secret)
wrong_sig = sign(fake_event, secret="attacker_guessed_wrong_secret")
r = c.post("/api/billing/webhook", content=fake_event,
           headers={"content-type": "application/json", "paddle-signature": wrong_sig})
check("webhook signed with the WRONG secret is rejected (400)", r.status_code == 400)

# 4. Valid signature for a DIFFERENT body than what's sent (tampered payload)
real_sig = sign(fake_event)
tampered_body = fake_event.replace(b"subscription.created", b"subscription.created!!")
r = c.post("/api/billing/webhook", content=tampered_body,
           headers={"content-type": "application/json", "paddle-signature": real_sig})
check("tampered body with a signature from a different body is rejected (400)", r.status_code == 400)

# None of the above forged attempts should have granted anything
r = c.get("/api/me", headers=auth)
check("user is STILL free after every forgery attempt", r.json()["is_premium"] is False)

# ---- a GENUINELY signed webhook is accepted and grants Pro ----
real_sig = sign(fake_event)
r = c.post("/api/billing/webhook", content=fake_event,
           headers={"content-type": "application/json", "paddle-signature": real_sig})
check("correctly signed webhook is accepted (200)", r.status_code == 200)
check("webhook response confirms it matched + handled the user",
      r.json()["matched_user"] if "matched_user" in r.json() else r.json()["handled"])

r = c.get("/api/me", headers=auth)
check("user is now Pro after the real webhook", r.json()["is_premium"] is True)

with Session(main.engine) as s:
    buyer = s.get(main.User, buyer_id)
    check("subscription_status stored as 'active'", buyer.subscription_status == "active")
    check("paddle_subscription_id stored", buyer.paddle_subscription_id == "sub_fake")
    check("paddle_customer_id stored", buyer.paddle_customer_id == "ctm_fake")

# ---- cancellation webhook correctly revokes access ----
cancel_event = json.dumps({
    "event_type": "subscription.canceled",
    "data": {"id": "sub_fake", "customer_id": "ctm_fake", "custom_data": {"user_id": str(buyer_id)}},
}).encode()
sig = sign(cancel_event)
r = c.post("/api/billing/webhook", content=cancel_event,
           headers={"content-type": "application/json", "paddle-signature": sig})
check("cancellation webhook accepted (200)", r.status_code == 200)
r = c.get("/api/me", headers=auth)
check("user loses Pro after a genuine cancellation webhook", r.json()["is_premium"] is False)

# ---- past_due keeps access (payment retry in progress), doesn't yet revoke ----
r2 = c.post("/api/register", json={"email": "pastdue@test.com", "password": "strongpass123"})
with Session(main.engine) as s:
    u2 = s.exec(select(main.User).where(main.User.email == "pastdue@test.com")).first()
    u2_id = u2.id
active_event = json.dumps({
    "event_type": "subscription.activated",
    "data": {"id": "sub_pd", "customer_id": "ctm_pd", "custom_data": {"user_id": str(u2_id)}},
}).encode()
c.post("/api/billing/webhook", content=active_event,
       headers={"content-type": "application/json", "paddle-signature": sign(active_event)})
past_due_event = json.dumps({
    "event_type": "subscription.past_due",
    "data": {"id": "sub_pd", "customer_id": "ctm_pd", "custom_data": {"user_id": str(u2_id)}},
}).encode()
c.post("/api/billing/webhook", content=past_due_event,
       headers={"content-type": "application/json", "paddle-signature": sign(past_due_event)})
with Session(main.engine) as s:
    u2 = s.get(main.User, u2_id)
    check("past_due keeps Pro access (retry pending, not a full cancellation)", u2.is_premium is True)
    check("past_due status recorded for visibility", u2.subscription_status == "past_due")

# ---- an unmatched webhook (no such user) is safely ignored, not an error ----
orphan_event = json.dumps({
    "event_type": "subscription.created",
    "data": {"id": "sub_orphan", "customer_id": "ctm_orphan", "custom_data": {"user_id": "999999"}},
}).encode()
r = c.post("/api/billing/webhook", content=orphan_event,
           headers={"content-type": "application/json", "paddle-signature": sign(orphan_event)})
check("webhook for a nonexistent user is accepted but grants nothing (no crash)",
      r.status_code == 200 and r.json().get("matched_user") is False)

# ---- an unrecognized event type doesn't crash, doesn't change anything ----
weird_event = json.dumps({
    "event_type": "something.unrecognized",
    "data": {"id": "sub_weird", "customer_id": "ctm_weird", "custom_data": {"user_id": str(buyer_id)}},
}).encode()
r = c.post("/api/billing/webhook", content=weird_event,
           headers={"content-type": "application/json", "paddle-signature": sign(weird_event)})
check("unrecognized event type handled gracefully (200, not crashed)", r.status_code == 200)

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"): os.remove("app.db")
