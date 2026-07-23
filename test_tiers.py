"""Tests for the Pro ($6.99) / Max ($9.99) plan tiers.

Focus: the new plan_tier/checkout_tier fields correctly thread a "pro" vs
"max" choice from checkout through to what gets granted, for both local
rails and all 5 grant points -- WITHOUT touching is_premium's existing
semantics (still just "has paid access", used by ~20 pre-existing gates).
Paddle's Max tier depends on Price objects created in the Paddle dashboard
(can't be exercised without live credentials), so only its config
passthrough is checked here.

Run: python test_tiers.py
"""
import os, datetime as dt
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["ZAINCASH_CLIENT_ID"] = "test_zaincash_client"
os.environ["ZAINCASH_CLIENT_SECRET"] = "test_zaincash_secret"
os.environ["QICARD_TERMINAL_ID"] = "test_terminal"
os.environ["QICARD_USERNAME"] = "test_qicard_user"
os.environ["QICARD_PASSWORD"] = "test_qicard_pass"
os.environ["PRO_PRICE_USD"] = "6.99"
os.environ["PRO_PRICE_IQD"] = "9100"
os.environ["MAX_PRICE_USD"] = "9.99"
os.environ["MAX_PRICE_IQD"] = "13000"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

# ---- pricing constants ----
check("PRO_PRICE_USD reflects the new $6.99", main.PRO_PRICE_USD == "6.99")
check("PRO_PRICE_IQD reflects the new 9100", main.PRO_PRICE_IQD == "9100")
check("MAX_PRICE_USD is 9.99", main.MAX_PRICE_USD == "9.99")
check("MAX_PRICE_IQD is 13000", main.MAX_PRICE_IQD == "13000")
check("MAX_PRICE_USD_ANNUAL defaults to 10x (99.90)", main.MAX_PRICE_USD_ANNUAL == "99.90")
check("MAX_PRICE_IQD_ANNUAL defaults to 10x (130000.00)", main.MAX_PRICE_IQD_ANNUAL == "130000.00")
check("User model defaults to plan_tier='pro'", main.User.__fields__["plan_tier"].default == "pro")
check("User model defaults to checkout_tier='pro'", main.User.__fields__["checkout_tier"].default == "pro")

class FakeResp:
    def __init__(self, json_body, ok=True, status_code=200):
        self._json = json_body; self.ok = ok; self.status_code = status_code; self.text = str(json_body)
    def json(self): return self._json
    def raise_for_status(self):
        if not self.ok: raise Exception(f"HTTP {self.status_code}")

_qi_counter = {"n": 0}
def fake_post(url, **kwargs):
    if url.endswith("/oauth2/token"):
        return FakeResp({"access_token": "fake_token", "expires_in": 3600})
    if url.endswith("/transaction/init"):
        _qi_counter["n"] += 1
        return FakeResp({"data": {"redirectUrl": f"https://pay.zaincash.iq/checkout?id=fake-zc-txn-{_qi_counter['n']}"}})
    if url.endswith("/api/v1/payment"):
        _qi_counter["n"] += 1
        pid = f"fake-qi-payment-{_qi_counter['n']}"
        return FakeResp({"paymentId": pid, "formUrl": f"https://pay.qi.iq/checkout/{pid}"})
    raise AssertionError(f"unexpected POST to {url}")
main.requests.post = fake_post

def new_user(email):
    r = c.post("/api/register", json={"email": email, "password": "strongpass123"})
    auth = {"Authorization": "Bearer " + r.json()["token"]}
    with Session(main.engine) as s:
        uid = s.exec(select(main.User).where(main.User.email == email)).first().id
    return uid, auth

# ---- billing_config exposes both tiers ----
zc_id, zc_auth = new_user("tier_zc@test.com")
cfg = c.get("/api/billing/config", headers=zc_auth).json()
check("billing_config: price_usd_max is 9.99", cfg["price_usd_max"] == "9.99")
check("billing_config: price_iqd_max is 13000", cfg["price_iqd_max"] == "13000")
check("billing_config: price_usd_max_annual is 99.90", cfg["price_usd_max_annual"] == "99.90")
check("billing_config: price_id_max empty (Paddle not configured)", cfg["price_id_max"] == "")
check("billing_config: price_id_max_annual empty (Paddle not configured)", cfg["price_id_max_annual"] == "")

# ---- new user starts on pro tier by default ----
with Session(main.engine) as s:
    u = s.get(main.User, zc_id)
    check("new user defaults to plan_tier='pro'", u.plan_tier == "pro")
    check("new user defaults to checkout_tier='pro'", u.checkout_tier == "pro")

# ---- ZainCash: checkout with tier='max' + plan='annual', grants max tier / 365 days ----
r = c.post("/api/billing/zaincash/checkout", json={"plan": "annual", "tier": "max"}, headers=zc_auth)
check("zaincash checkout (max, annual) succeeds", r.status_code == 200 and "redirect_url" in r.json())
with Session(main.engine) as s:
    u = s.get(main.User, zc_id)
    check("checkout stored checkout_tier='max'", u.checkout_tier == "max")
    check("checkout stored checkout_plan='annual'", u.checkout_plan == "annual")

main.zaincash_inquiry = lambda txn_id: "SUCCESS"
with Session(main.engine) as s:
    granted = main._confirm_and_grant_zaincash(f"speakup-{zc_id}-1", s)
    check("_confirm_and_grant_zaincash returns True", granted is True)
    u = s.get(main.User, zc_id)
    check("granted user's plan_tier is 'max'", u.plan_tier == "max")
    check("granted user is_premium (tier is separate from is_premium)", u.is_premium is True)
    days = (u.pro_expires_at - dt.datetime.utcnow()).days
    check(f"annual duration still correct alongside max tier (got {days})", 363 <= days <= 365)

# ---- an invalid tier value silently falls back to 'pro' ----
bad_id, bad_auth = new_user("tier_bad@test.com")
r = c.post("/api/billing/zaincash/checkout", json={"plan": "monthly", "tier": "ultra"}, headers=bad_auth)
check("checkout with bogus tier still succeeds (200)", r.status_code == 200)
with Session(main.engine) as s:
    u = s.get(main.User, bad_id)
    check("bogus tier value defaults to 'pro', not stored verbatim", u.checkout_tier == "pro")
r = c.post("/api/billing/zaincash/sync", headers=bad_auth)
with Session(main.engine) as s:
    u = s.get(main.User, bad_id)
    check("zaincash /sync granted plan_tier='pro' for the default checkout", u.plan_tier == "pro")

# ---- QiCard: checkout with tier='max' (monthly), grants max tier / 30 days ----
qi_id, qi_auth = new_user("tier_qi@test.com")
r = c.post("/api/billing/qicard/checkout", json={"plan": "monthly", "tier": "max"}, headers=qi_auth)
check("qicard checkout (max, monthly) succeeds", r.status_code == 200 and "redirect_url" in r.json())
with Session(main.engine) as s:
    u = s.get(main.User, qi_id)
    check("qicard checkout stored checkout_tier='max'", u.checkout_tier == "max")

main.qicard_get_status = lambda payment_id: "SUCCESS"
with Session(main.engine) as s:
    granted = main._confirm_and_grant_qicard(qi_id, s)
    check("_confirm_and_grant_qicard returns True", granted is True)
    u = s.get(main.User, qi_id)
    check("qicard-granted user's plan_tier is 'max'", u.plan_tier == "max")
    days = (u.pro_expires_at - dt.datetime.utcnow()).days
    check(f"monthly duration still correct alongside max tier (got {days})", 28 <= days <= 30)

# ---- qicard webhook also threads the tier through ----
wh_id, wh_auth = new_user("tier_wh@test.com")
c.post("/api/billing/qicard/checkout", json={"plan": "monthly", "tier": "max"}, headers=wh_auth)
with Session(main.engine) as s:
    real_payment_id = s.get(main.User, wh_id).qicard_payment_id
r = c.post("/api/billing/qicard/webhook", json={"paymentId": real_payment_id})
check("qicard webhook accepted", r.status_code == 200)
with Session(main.engine) as s:
    u = s.get(main.User, wh_id)
    check("qicard webhook granted plan_tier='max'", u.plan_tier == "max")

# ---- public_user() / GET /api/me exposes plan_tier ----
r = c.get("/api/me", headers=zc_auth)
check("/api/me exposes plan_tier", r.json()["plan_tier"] == "max")
check("/api/me still exposes is_premium unaffected by tier concept", r.json()["is_premium"] is True)

# ---- existing ~20 is_premium gates are untouched: a Pro (non-max) user still is_premium ----
pro_id, pro_auth = new_user("tier_pro_only@test.com")
c.post("/api/billing/qicard/checkout", json={"plan": "monthly", "tier": "pro"}, headers=pro_auth)
with Session(main.engine) as s:
    real_payment_id = s.get(main.User, pro_id).qicard_payment_id
c.post("/api/billing/qicard/webhook", json={"paymentId": real_payment_id})
r = c.get("/api/me", headers=pro_auth)
check("plain Pro buyer is_premium (unaffected by tier feature)", r.json()["is_premium"] is True)
check("plain Pro buyer plan_tier is 'pro', not 'max'", r.json()["plan_tier"] == "pro")

# ---- UpgradeIn model (demo-mode /api/upgrade payload) defaults + accepts tier ----
check("UpgradeIn() defaults to tier='pro'", main.UpgradeIn().tier == "pro")
check("UpgradeIn(tier='max') round-trips", main.UpgradeIn(tier="max").tier == "max")

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"): os.remove("app.db")
