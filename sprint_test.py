"""Tests for the 14-Day Sprint (now two stages: drill, then a CLT
conversation). Run: python sprint_test.py
"""
import os, datetime as dt
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["GEMINI_API_KEY"] = "test-key"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import app, engine, Enrollment, SPRINT

# Mock the AI so this test needs no real key and costs nothing.
def fake_json(system, messages, max_tokens=1200):
    n = len([m for m in messages if m["role"] == "user"])
    return {"reply": "Sure, let's talk about it.",
            "goals_met": [] if n < 2 else ["placeholder"], "done": n >= 2}
main.ai_json = fake_json

c = TestClient(app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

def rewind(user_id, days):
    """Pretend the user enrolled `days` days ago (time travel for testing)."""
    with Session(engine) as s:
        e = s.exec(select(Enrollment).where(Enrollment.user_id == user_id)).first()
        e.started_at = dt.datetime.utcnow() - dt.timedelta(days=days)
        s.add(e); s.commit()

def do_drill(auth, day, score):
    return c.post("/api/sprint/day/complete", headers=auth, json={"day": day, "avg_score": score})

def do_conv(auth, day):
    """Simulate finishing the day's conversation: 2 chat turns, then mark it done."""
    c.post("/api/chat", headers=auth, json={"scenario_id": f"sprintday{day}", "message": ""})
    c.post("/api/chat", headers=auth, json={"scenario_id": f"sprintday{day}", "message": "ok"})
    return c.post("/api/sprint/day/conv-complete", headers=auth, json={"day": day})

# setup user
r = c.post("/api/register", json={"email":"sprint@test.com","password":"strongpass123"})
auth = {"Authorization": "Bearer " + r.json()["token"]}

# free user cannot enroll
r = c.post("/api/sprint/enroll", headers=auth)
check("free user blocked from Sprint (403)", r.status_code == 403)

# sprint content hidden from free user
r = c.get("/api/sprint", headers=auth)
check("all days locked + content hidden for free user",
      all(d["locked"] and d["phrases"] == [] and d["challenge"] == "" and d["conv"] is None
          for d in r.json()["days"]))
check("sprint has 14 days", len(r.json()["days"]) == 14)

# upgrade
c.post("/api/upgrade", headers=auth)

# still must enroll before days open
r = c.get("/api/sprint", headers=auth)
check("premium but not enrolled -> still locked", all(d["locked"] for d in r.json()["days"]))
check("state shows not enrolled", r.json()["state"]["enrolled"] is False)

# enroll
r = c.post("/api/sprint/enroll", headers=auth)
check("enroll works", r.status_code == 200 and r.json()["enrolled"] is True)
check("day 1 unlocked on enroll", r.json()["unlocked_through"] == 1)

# double enroll blocked
r = c.post("/api/sprint/enroll", headers=auth)
check("double enroll rejected", r.status_code == 400)

# only day 1 open, WITH a conversation attached
r = c.get("/api/sprint", headers=auth)
days = r.json()["days"]
check("day 1 open with phrases", (not days[0]["locked"]) and len(days[0]["phrases"]) == 5)
check("day 1 has a challenge", len(days[0]["challenge"]) > 0)
check("day 1 has a conversation with goals", days[0]["conv"] is not None and len(days[0]["conv"]["goals"]) >= 1)
check("day 2 still locked (content hidden)", days[1]["locked"] and days[1]["phrases"] == [] and days[1]["conv"] is None)

# THE KEY RULE: cannot skip ahead
r = do_drill(auth, 5, 95)
check("cannot skip ahead to day 5 (403)", r.status_code == 403)

# cannot pass a day with a low score
r = do_drill(auth, 1, 40)
check("low score rejected (needs 70%)", r.status_code == 400)

# --- STAGE 1: pass the drill for day 1 ---
r = do_drill(auth, 1, 88)
check("drill stage passes", r.status_code == 200)
check("day NOT fully cleared yet (conversation still owed)", r.json()["completed_days"] == [])
check("drill_done_days shows day 1", r.json()["drill_done_days"] == [1])

# you cannot start a day's conversation before that day's drill is done
r = c.post("/api/chat", headers=auth, json={"scenario_id": "sprintday2", "message": ""})
check("conversation blocked before that day's drill is done (400/403)", r.status_code in (400, 403))

# --- STAGE 2: have the conversation for day 1 ---
r = c.post("/api/chat", headers=auth, json={"scenario_id": "sprintday1", "message": ""})
check("sprint-day conversation opens", r.status_code == 200 and r.json()["reply"])
r = c.post("/api/sprint/day/conv-complete", headers=auth, json={"day": 1})
check("conversation stage completes day 1", r.status_code == 200)
check("day 1 NOW fully cleared", r.json()["completed_days"] == [1])
check("streak = 1", r.json()["streak"] == 1)
check("percent ~7%", r.json()["percent"] == 7)

# day 2 still not available same day
r = do_drill(auth, 2, 90)
check("day 2 drill locked until tomorrow (403)", r.status_code == 403)

# time travel 1 day -> day 2 opens
rewind(1, 1)
r = c.get("/api/sprint", headers=auth)
check("after 1 day, day 2 unlocked", r.json()["state"]["unlocked_through"] == 2)
check("after 1 day, day 3 still locked", r.json()["days"][2]["locked"])

r = do_drill(auth, 2, 76)
check("day 2 drill passes", r.status_code == 200)
r = do_conv(auth, 2)
check("day 2 fully cleared after both stages", r.status_code == 200 and r.json()["streak"] == 2)

# best drill score kept on repeat
do_drill(auth, 2, 95)
r = c.get("/api/sprint", headers=auth)
check("repeat drill keeps best score", r.json()["state"]["scores_by_day"]["2"] == 95)

# no certificate yet
r = c.get("/api/sprint/certificate", headers=auth)
check("certificate blocked before finishing (403)", r.status_code == 403)

# time travel 13 days -> all unlocked, finish everything (both stages, every day)
rewind(1, 13)
r = c.get("/api/sprint", headers=auth)
check("after 13 days all 14 unlocked", r.json()["state"]["unlocked_through"] == 14)
for d in range(3, 15):
    do_drill(auth, d, 90)
    do_conv(auth, d)
r = c.get("/api/sprint", headers=auth)
st = r.json()["state"]
check("all 14 days complete", st["finished"] is True and st["percent"] == 100)
check("streak = 14", st["streak"] == 14)

# certificate now issued
r = c.get("/api/sprint/certificate", headers=auth)
check("certificate issued after finishing", r.status_code == 200 and r.json()["avg_score"] > 0)

# a second user is fully separate
r = c.post("/api/register", json={"email":"other@test.com","password":"strongpass123"})
auth2 = {"Authorization": "Bearer " + r.json()["token"]}
r = c.get("/api/sprint", headers=auth2)
check("second user has own empty state", r.json()["state"]["enrolled"] is False)

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
