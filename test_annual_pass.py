"""Tests for the annual Pro pass option (ZainCash + QiCard + billing_config).

Focus: the new checkout_plan field correctly threads a "monthly" vs "annual"
choice from checkout all the way through to the number of days granted, for
BOTH local payment rails and all five grant points (checkout x2, confirm-
and-grant x2, sync x2, webhook x1). Paddle's annual option depends on a
second Price object created in the Paddle dashboard (can't be exercised
without live credentials) so only its config passthrough is checked here --
Paddle's actual charge path is already covered by billing_test.py.

Outbound HTTP calls to ZainCash/QiCard's real APIs are stubbed (this test
never hits the network); only OUR OWN plan-aware logic is under test.
Run: python test_annual_pass.py
"""
import os, datetime as dt
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["ZAINCASH_CLIENT_ID"] = "test_zaincash_client"
os.environ["ZAINCASH_CLIENT_SECRET"] = "test_zaincash_secret"
os.environ["QICARD_TERMINAL_ID"] = "test_terminal"
os.environ["QICARD_USERNAME"] = "test_qicard_user"
os.environ["QICARD_PASSWORD"] = "test_qicard_pass"
os.environ["PRO_PRICE_USD"] = "4.99"
os.environ["PRO_PRICE_IQD"] = "6500"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

check("ZainCash detected as configured", main.ZAINCASH_CONFIGURED is True)
check("QiCard detected as configured", main.QICARD_CONFIGURED is True)
check("Paddle NOT configured in this test", main.PADDLE_CONFIGURED is False)

check("_default_annual: 10x monthly, 2dp ('4.99' -> '49.90')", main._default_annual("4.99") == "49.90")
check("_default_annual: 10x monthly, 2dp ('6500' -> '65000.00')", main._default_annual("6500") == "65000.00")
check("_default_annual: falls back to input on bad data", main._default_annual("not-a-number") == "not-a-number")
check("PRO_PLAN_DAYS: monthly=30", main.PRO_PLAN_DAYS.get("monthly") == 30)
check("PRO_PLAN_DAYS: annual=365", main.PRO_PLAN_DAYS.get("annual") == 365)
check("PRO_PRICE_USD_ANNUAL picked up the default (no env override set)", main.PRO_PRICE_USD_ANNUAL == "49.90")
check("PRO_PRICE_IQD_ANNUAL picked up the default (no env override set)", main.PRO_PRICE_IQD_ANNUAL == "65000.00")

class FakeResp:
    def __init__(self, json_body, ok=True, status_code=200):
        self._json = json_body
        self.ok = ok
        self.status_code = status_code
        self.text = str(json_body)
    def json(self): return self._json
    def raise_for_status(self):
        if not self.ok: raise Exception(f"HTTP {self.status_code}")

_qi_payment_counter = {"n": 0}

def fake_post(url, **kwargs):
    if url.endswith("/oauth2/token"):
        return FakeResp({"access_token": "fake_token", "expires_in": 3600})
    if url.endswith("/transaction/init"):
        return FakeResp({"data": {"redirectUrl": "https://pay.zaincash.iq/checkout?id=fake-zc-txn-1"}})
    if url.endswith("/api/v1/payment"):
        # Real QiCard would never hand out the same paymentId to two
        # different checkouts -- a fixed string here would make every buyer
        # collide onto one row and silently corrupt this test.
        _qi_payment_counter["n"] += 1
        pid = f"fake-qi-payment-{_qi_payment_counter['n']}"
        return FakeResp({"paymentId": pid, "formUrl": f"https://pay.qi.iq/checkout/{pid}"})
    raise AssertionError(f"unexpected POST to {url}")

main.requests.post = fake_post

r = c.post("/api/register", json={"email": "zc_buyer@test.com", "password": "strongpass123"})
zc_auth = {"Authorization": "Bearer " + r.json()["token"]}
with Session(main.engine) as s:
    zc_user = s.exec(select(main.User).where(main.User.email == "zc_buyer@test.com")).first()
    zc_id = zc_user.id
    check("new user starts with checkout_plan='monthly' (default)", zc_user.checkout_plan == "monthly")

r = c.post("/api/register", json={"email": "qi_buyer@test.com", "password": "strongpass123"})
qi_auth = {"Authorization": "Bearer " + r.json()["token"]}
with Session(main.engine) as s:
    qi_user = s.exec(select(main.User).where(main.User.email == "qi_buyer@test.com")).first()
    qi_id = qi_user.id

r = c.get("/api/billing/config", headers=zc_auth)
cfg = r.json()
check("billing_config: both local providers listed", {p["id"] for p in cfg["local_providers"]} == {"zaincash", "qicard"})
check("billing_config: price_usd_annual is the 10x default", cfg["price_usd_annual"] == "49.90")
check("billing_config: price_iqd_annual is the 10x default", cfg["price_iqd_annual"] == "65000.00")
check("billing_config: price_id_annual empty (Paddle not configured)", cfg["price_id_annual"] == "")

r = c.post("/api/billing/zaincash/checkout", json={"plan": "annual"}, headers=zc_auth)
check("zaincash checkout (annual) returns a redirect_url", r.status_code == 200 and "redirect_url" in r.json())
with Session(main.engine) as s:
    zc_user = s.get(main.User, zc_id)
    check("zaincash checkout (annual) stored checkout_plan='annual'", zc_user.checkout_plan == "annual")
    check("zaincash checkout stored the transaction id from the redirect URL", zc_user.zaincash_transaction_id == "fake-zc-txn-1")

main.zaincash_inquiry = lambda txn_id: "SUCCESS"
with Session(main.engine) as s:
    granted = main._confirm_and_grant_zaincash(f"speakup-{zc_id}-9999", s)
    check("_confirm_and_grant_zaincash returns True on SUCCESS", granted is True)
    zc_user = s.get(main.User, zc_id)
    check("zaincash annual grant sets is_premium", zc_user.is_premium is True)
    days_granted = (zc_user.pro_expires_at - dt.datetime.utcnow()).days
    check(f"zaincash annual grant gives ~365 days, not 30 (got {days_granted})", 363 <= days_granted <= 365)

r = c.post("/api/register", json={"email": "zc_bad_plan@test.com", "password": "strongpass123"})
bad_auth = {"Authorization": "Bearer " + r.json()["token"]}
with Session(main.engine) as s:
    bad_id = s.exec(select(main.User).where(main.User.email == "zc_bad_plan@test.com")).first().id
r = c.post("/api/billing/zaincash/checkout", json={"plan": "lifetime"}, headers=bad_auth)
check("zaincash checkout with a bogus plan value still succeeds (200)", r.status_code == 200)
with Session(main.engine) as s:
    bad_user = s.get(main.User, bad_id)
    check("bogus plan value defaults to 'monthly', not stored verbatim", bad_user.checkout_plan == "monthly")

r = c.post("/api/billing/zaincash/checkout", json={}, headers=bad_auth)
with Session(main.engine) as s:
    bad_user = s.get(main.User, bad_id)
    check("checkout with plan omitted defaults to 'monthly'", bad_user.checkout_plan == "monthly")
r = c.post("/api/billing/zaincash/sync", headers=bad_auth)
with Session(main.engine) as s:
    bad_user = s.get(main.User, bad_id)
    check("zaincash /sync granted monthly Pro", bad_user.is_premium is True)
    days_granted = (bad_user.pro_expires_at - dt.datetime.utcnow()).days
    check(f"zaincash /sync (monthly) gives ~30 days, not 365 (got {days_granted})", 28 <= days_granted <= 30)

r = c.post("/api/billing/qicard/checkout", json={"plan": "annual"}, headers=qi_auth)
check("qicard checkout (annual) returns a redirect_url", r.status_code == 200 and "redirect_url" in r.json())
with Session(main.engine) as s:
    qi_user = s.get(main.User, qi_id)
    check("qicard checkout (annual) stored checkout_plan='annual'", qi_user.checkout_plan == "annual")
    check("qicard checkout stored the payment id", qi_user.qicard_payment_id == "fake-qi-payment-1")

main.qicard_get_status = lambda payment_id: "SUCCESS"
with Session(main.engine) as s:
    granted = main._confirm_and_grant_qicard(qi_id, s)
    check("_confirm_and_grant_qicard returns True on SUCCESS", granted is True)
    qi_user = s.get(main.User, qi_id)
    days_granted = (qi_user.pro_expires_at - dt.datetime.utcnow()).days
    check(f"qicard annual grant gives ~365 days, not 30 (got {days_granted})", 363 <= days_granted <= 365)

r = c.post("/api/register", json={"email": "qi_webhook@test.com", "password": "strongpass123"})
wh_auth = {"Authorization": "Bearer " + r.json()["token"]}
with Session(main.engine) as s:
    wh_id = s.exec(select(main.User).where(main.User.email == "qi_webhook@test.com")).first().id
c.post("/api/billing/qicard/checkout", json={"plan": "annual"}, headers=wh_auth)
with Session(main.engine) as s:
    real_payment_id = s.get(main.User, wh_id).qicard_payment_id
r = c.post("/api/billing/qicard/webhook", json={"paymentId": real_payment_id})
check("qicard webhook accepted (200)", r.status_code == 200)
with Session(main.engine) as s:
    wh_user = s.get(main.User, wh_id)
    check("qicard webhook granted Pro", wh_user.is_premium is True)
    days_granted = (wh_user.pro_expires_at - dt.datetime.utcnow()).days
    check(f"qicard webhook (annual) gives ~365 days, not 30 (got {days_granted})", 363 <= days_granted <= 365)

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"): os.remove("app.db")
