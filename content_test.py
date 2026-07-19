"""Tests for the offline content engine (no API). Run: python content_test.py"""
import os
if os.path.exists("app.db"):
    os.remove("app.db")

import main
from fastapi.testclient import TestClient
from content import SENTENCE_BANK, CONVERSATIONS, SPRINT_CONVS

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

r = c.post("/api/register", json={"email": "off@test.com", "password": "strongpass123"})
auth = {"Authorization": "Bearer " + r.json()["token"]}

# ---- sentence bank ----
check("bank has 3 levels", set(SENTENCE_BANK) == {"Beginner","Intermediate","Advanced"})
check("every bank sentence has an Arabic translation",
      all(s.get("en") and s.get("ar") for lvl in SENTENCE_BANK.values() for s in lvl))

r = c.post("/api/sentences", headers=auth, json={"level":"Beginner","count":10})
body = r.json()
check("sentences endpoint returns requested count", len(body["sentences"]) == 10)
check("sentences come with translations baked in",
      all(s in body["translations"] for s in body["sentences"]))
check("no API key needed — endpoint works offline", r.status_code == 200)

# avoid list prevents immediate repeats
seen = body["sentences"]
r2 = c.post("/api/sentences", headers=auth, json={"level":"Beginner","count":10,"avoid":seen})
overlap = set(seen) & set(r2.json()["sentences"])
check("avoid list reduces repeats", len(overlap) < 5)

# count is clamped
r = c.post("/api/sentences", headers=auth, json={"level":"Beginner","count":999})
check("count clamped to <=30", len(r.json()["sentences"]) <= 30)

# ---- translation (offline lookup) ----
sample = SENTENCE_BANK["Beginner"][0]
r = c.post("/api/translate", headers=auth, json={"text": sample["en"], "lang":"ar"})
check("translation resolves from the bank instantly",
      r.json()["translated"] == sample["ar"] and r.json()["found"] is True)
r = c.post("/api/translate", headers=auth, json={"text": "something not in the bank", "lang":"ar"})
check("unknown text returns not-found gracefully", r.json()["found"] is False)

# ---- scenarios list ----
r = c.get("/api/scenarios", headers=auth)
body = r.json()
check("scenarios listed", len(body["scenarios"]) == len(CONVERSATIONS))
check("ai_ready is always true (offline)", body["ai_ready"] is True)
free = [s for s in body["scenarios"] if not s["is_premium"]]
prem = [s for s in body["scenarios"] if s["is_premium"]]
check("free scenarios expose their goal", all(s["goal"] for s in free))
check("premium scenarios locked + hidden for free user",
      all(s["locked"] and s["goal"] == "" for s in prem))

# ---- open a free conversation ----
r = c.get("/api/conversation/cafe", headers=auth)
conv = r.json()
check("conversation returns a node tree", r.status_code == 200 and len(conv["nodes"]) >= 3)
check("conversation has a start node", conv["start"] in [n["id"] for n in conv["nodes"]])

# every reply points to a real node
node_ids = {n["id"] for n in conv["nodes"]}
all_gotos_valid = all(rep["goto"] in node_ids
                      for n in conv["nodes"] for rep in n.get("replies", []))
check("every reply leads to a real node (no dead links)", all_gotos_valid)
check("conversation lines carry Arabic translations",
      all(n["npc"].get("ar") for n in conv["nodes"]))

# premium conversation blocked for free user
r = c.get("/api/conversation/interview", headers=auth)
check("premium conversation blocked for free user", r.status_code == 403)

# ---- validate ALL conversations are well-formed (no broken trees) ----
def tree_ok(nodes, start):
    ids = {n["id"] for n in nodes}
    if start not in ids: return False
    for n in nodes:
        for rep in n.get("replies", []):
            if rep["goto"] not in ids: return False
        # non-end nodes should have replies; end nodes shouldn't need them
        if not n.get("end") and not n.get("replies"):
            return False
    return True

all_scenarios_ok = all(tree_ok(cv["nodes"], cv["start"]) for cv in CONVERSATIONS)
check("all standalone conversations are well-formed trees", all_scenarios_ok)

all_sprint_ok = all(tree_ok(d["nodes"], d["start"]) for d in SPRINT_CONVS.values())
check("all 14 sprint-day conversations are well-formed trees", all_sprint_ok)
check("sprint has a conversation for every one of its 14 days",
      set(SPRINT_CONVS.keys()) == set(range(1, 15)))

# ---- sprint-day conversation is gated correctly ----
r = c.get("/api/conversation/sprintday1", headers=auth)
check("sprint-day conv blocked for non-Pro / not-enrolled", r.status_code in (400, 403))

# upgrade + enroll + finish drill -> then conversation opens
c.post("/api/upgrade", headers=auth)
c.post("/api/sprint/enroll", headers=auth)
r = c.get("/api/conversation/sprintday1", headers=auth)
check("sprint-day conv still blocked before drill done", r.status_code == 400)
c.post("/api/sprint/day/complete", headers=auth, json={"day":1, "avg_score":90})
r = c.get("/api/conversation/sprintday1", headers=auth)
check("sprint-day conv opens after drill is done", r.status_code == 200 and len(r.json()["nodes"]) >= 2)

# ---- no API key or network is ever required ----
import inspect
src = inspect.getsource(main)
check("main.py imports no httpx (no network calls)", "import httpx" not in src)
check("main.py has no API-key config left", "ANTHROPIC_API_KEY" not in src and "GEMINI_API_KEY" not in src)

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
