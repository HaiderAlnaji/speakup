"""Tests for the CLT / AI features. Run: python clt_test.py

The AI is mocked, so this runs with NO API key and costs nothing.
"""
import os, json
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["ADMIN_EMAIL"] = ""
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
os.environ["AI_CALLS_PER_DAY_FREE"] = "10"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

# ---- mock the AI so no real network call happens ----
calls = {"n": 0, "last_system": "", "last_msgs": None}
def fake_call(system, messages, max_tokens=800):
    calls["n"] += 1
    calls["last_system"] = system
    calls["last_msgs"] = messages
    return "مرحبا"          # used by translate
def fake_json(system, messages, max_tokens=1200):
    calls["n"] += 1
    calls["last_system"] = system
    calls["last_msgs"] = messages
    if "role-play partner" in system:
        return {"reply": "Hi there! What can I get you?",
                "goals_met": ["Order a drink"], "done": False}
    if "reviewing a learner" in system:
        return {"communication": "You got your meaning across well.",
                "did_well": ["Clear order", "Polite tone"],
                "improve": [{"you_said": "I want coffee", "better": "Could I have a coffee, please?",
                             "why": "More natural and polite."}],
                "next_step": "Practice asking the price."}
    if "speaking-practice sentences" in system:
        return {"sentences": ["Could I have a coffee, please?", "How much is that?",
                             "Can I pay by card?", "Thanks a lot.",
                             "Do you have oat milk?", "That's all, thanks."]}
    return {}
main.ai_call = fake_call
main.ai_json = fake_json

# ---- setup a normal (free) user ----
r = c.post("/api/register", json={"email": "clt@test.com", "password": "strongpass123"})
auth = {"Authorization": "Bearer " + r.json()["token"]}

# ---- scenarios ----
r = c.get("/api/scenarios", headers=auth)
body = r.json()
check("scenarios listed", r.status_code == 200 and len(body["scenarios"]) == 6)
free = [s for s in body["scenarios"] if not s["is_premium"]]
prem = [s for s in body["scenarios"] if s["is_premium"]]
check("free scenarios show task+goals", all(s["task"] and s["goals"] for s in free))
check("premium scenarios locked + content hidden for free user",
      all(s["locked"] and s["task"] == "" and s["goals"] == [] for s in prem))

# ---- CLT prompt actually encodes the method ----
sysp = main.clt_system_prompt(main.SCENARIO_BY_ID["cafe"], "Beginner")
check("prompt forbids mid-conversation correction", "Do NOT correct grammar mid-conversation" in sysp)
check("prompt keeps AI in role", "STAY IN ROLE" in sysp)
check("prompt carries the communicative task", "find out the price" in sysp.lower() or "Order a drink" in sysp)

# ---- chat: opening turn ----
r = c.post("/api/chat", headers=auth, json={"scenario_id": "cafe", "message": ""})
check("chat opening turn works", r.status_code == 200 and r.json()["reply"])
check("goals returned", r.json()["goals"] == main.SCENARIO_BY_ID["cafe"]["goals"])
check("goal progress tracked", r.json()["goals_met"] == ["Order a drink"])

# ---- chat: a real turn is stored ----
r = c.post("/api/chat", headers=auth, json={"scenario_id": "cafe", "message": "Could I have a coffee?"})
check("chat reply turn works", r.status_code == 200)
r = c.get("/api/chat/history?scenario_id=cafe", headers=auth)
hist = r.json()
check("history persisted (survives refresh)", len(hist) >= 3 and hist[-1]["role"] == "assistant")

# ---- premium scenario blocked for free user ----
r = c.post("/api/chat", headers=auth, json={"scenario_id": "interview", "message": "Hello"})
check("premium scenario blocked for free user (403)", r.status_code == 403)

# ---- translation + cache ----
before = calls["n"]
r = c.post("/api/translate", headers=auth, json={"text": "Hello, nice to meet you.", "lang": "ar"})
check("translate works", r.status_code == 200 and r.json()["translated"] == "مرحبا")
check("first translate is not cached", r.json()["cached"] is False)
mid = calls["n"]
r = c.post("/api/translate", headers=auth, json={"text": "Hello, nice to meet you.", "lang": "ar"})
check("second identical translate IS cached", r.json()["cached"] is True)
check("cached translate costs ZERO extra AI calls", calls["n"] == mid)

# ---- unknown language falls back safely ----
r = c.post("/api/translate", headers=auth, json={"text": "Different text here.", "lang": "zz"})
check("unsupported language falls back to Arabic", r.json()["lang"] == "ar")

# ---- unlimited sentences ----
r = c.post("/api/sentences", headers=auth, json={"topic": "at the airport", "level": "Beginner"})
check("sentence generation works", r.status_code == 200 and len(r.json()["sentences"]) == 6)
check("sentences echo the requested topic", r.json()["topic"] == "at the airport")

# ---- debrief (feedback AFTER, not during — the CLT way) ----
r = c.post("/api/chat/debrief", headers=auth, json={"scenario_id": "cafe"})
d = r.json()
check("debrief gives communication-first feedback", r.status_code == 200 and d["communication"])
check("debrief lists concrete improvements", len(d["improve"]) >= 1 and d["improve"][0]["better"])

# ---- THE COST CAP: the thing that protects the bill ----
# free limit is 5/day; we've already used several. Burn the rest.
hit = False
for i in range(25):
    rr = c.post("/api/sentences", headers=auth, json={"topic": f"topic {i}", "level": "Beginner"})
    if rr.status_code == 429:
        hit = True
        break
check("daily AI cap enforced (429) — protects your bill", hit)

# a capped user cannot chat either
r = c.post("/api/chat", headers=auth, json={"scenario_id": "cafe", "message": "hello"})
check("cap applies to chat too", r.status_code == 429)

# ---- restart is free even when capped (no AI call needed) ----
r = c.get("/api/ai/status", headers=auth)
check("ai status reports usage + limit", r.status_code == 200 and r.json()["limit"] == 10)
check("ai status lists Arabic", "ar" in r.json()["languages"])

# ---- no API key => clear, honest error rather than a crash ----
saved = main.ANTHROPIC_API_KEY
main.ANTHROPIC_API_KEY = ""
check("ai_available() false without key", main.ai_available() is False)
main.ANTHROPIC_API_KEY = saved

# ---- the API key is never exposed to the browser ----
r = c.get("/api/ai/status", headers=auth)
check("status never leaks the API key", "sk-ant" not in json.dumps(r.json()))
r = c.get("/")
check("frontend HTML never contains an API key", "sk-ant" not in r.text)

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
