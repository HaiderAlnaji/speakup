"""Tests for the AI Roleplay feature (Gemini-powered, Max-only).

Focus: the require_max gate rejects free/Pro users before any Gemini call is
made, GEMINI_CONFIGURED correctly reports whether GEMINI_API_KEY is set, and
call_gemini() correctly builds the request and parses a realistic response.
requests.post is faked throughout -- no real network call, no real API key
needed to run this.

Run: python test_roleplay.py
"""
import os
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["GEMINI_API_KEY"] = "test_gemini_key"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

check("GEMINI_CONFIGURED is True once GEMINI_API_KEY is set", main.GEMINI_CONFIGURED is True)

class FakeResp:
    def __init__(self, json_body, ok=True, status_code=200, text=""):
        self._json = json_body; self.ok = ok; self.status_code = status_code
        self.text = text or str(json_body)
    def json(self): return self._json

_last_request = {}
def fake_post(url, **kwargs):
    if "generativelanguage.googleapis.com" in url:
        _last_request["url"] = url
        _last_request["json"] = kwargs.get("json")
        _last_request["params"] = kwargs.get("params")
        return FakeResp({"candidates": [{"content": {"parts": [{"text": "Hi there! What brings you in today?"}]}}]})
    raise AssertionError(f"unexpected POST to {url}")
main.requests.post = fake_post

def new_user(email):
    r = c.post("/api/register", json={"email": email, "password": "strongpass123"})
    auth = {"Authorization": "Bearer " + r.json()["token"]}
    with Session(main.engine) as s:
        u = s.exec(select(main.User).where(main.User.email == email)).first()
        uid = u.id
    return uid, auth

def set_tier(uid, is_premium, plan_tier):
    with Session(main.engine) as s:
        u = s.get(main.User, uid)
        u.is_premium = is_premium
        u.plan_tier = plan_tier
        s.add(u); s.commit()

# ---- no auth at all ----
r = c.post("/api/roleplay/reply", json={"message": "hi"})
check("no auth -> 401", r.status_code == 401)

# ---- free user ----
free_id, free_auth = new_user("rp_free@test.com")
r = c.post("/api/roleplay/reply", json={"message": "hi"}, headers=free_auth)
check("free user -> 403 (Max only)", r.status_code == 403)

# ---- pro (not max) user ----
pro_id, pro_auth = new_user("rp_pro@test.com")
set_tier(pro_id, True, "pro")
r = c.post("/api/roleplay/reply", json={"message": "hi"}, headers=pro_auth)
check("pro (non-max) user -> 403 (Max only)", r.status_code == 403)

# ---- max user, real call path ----
max_id, max_auth = new_user("rp_max@test.com")
set_tier(max_id, True, "max")

r = c.get("/api/ai/status", headers=max_auth)
check("/api/ai/status ready:true when GEMINI_API_KEY set", r.json().get("ready") is True)

r = c.post("/api/roleplay/reply",
           json={"scenario": "Ordering coffee", "history": [{"role": "ai", "text": "Hi, welcome!"}], "message": "One latte please"},
           headers=max_auth)
check("max user -> 200", r.status_code == 200)
check("reply text parsed correctly from Gemini response", r.json().get("reply") == "Hi there! What brings you in today?")
check("scenario text reached the system_instruction", "Ordering coffee" in _last_request["json"]["system_instruction"]["parts"][0]["text"])
check("prior AI turn mapped to role='model'", _last_request["json"]["contents"][0] == {"role": "model", "parts": [{"text": "Hi, welcome!"}]})
check("new message appended as final role='user' turn", _last_request["json"]["contents"][-1] == {"role": "user", "parts": [{"text": "One latte please"}]})
check("API key sent as query param, not in body", _last_request["params"] == {"key": "test_gemini_key"})

# ---- empty message rejected before ever calling Gemini ----
_last_request.clear()
r = c.post("/api/roleplay/reply", json={"message": "   "}, headers=max_auth)
check("blank message -> 400", r.status_code == 400)
check("blank message never reached Gemini", not _last_request)

# ---- Gemini safety-block / malformed response handled gracefully ----
def fake_post_blocked(url, **kwargs):
    return FakeResp({"candidates": [{"finishReason": "SAFETY"}]})
main.requests.post = fake_post_blocked
r = c.post("/api/roleplay/reply", json={"message": "hi"}, headers=max_auth)
check("safety-blocked Gemini response -> 502, not a 500 crash", r.status_code == 502)

# ---- Gemini HTTP error surfaced, not swallowed ----
def fake_post_error(url, **kwargs):
    return FakeResp({}, ok=False, status_code=429, text="rate limited")
main.requests.post = fake_post_error
r = c.post("/api/roleplay/reply", json={"message": "hi"}, headers=max_auth)
check("Gemini HTTP error -> 502 with detail", r.status_code == 502 and "429" in r.json()["detail"])

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"):
    os.remove("app.db")
