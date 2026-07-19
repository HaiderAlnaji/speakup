"""Quick in-process test of the whole API. Run: python smoke_test.py"""
import os
# fresh DB for the test
if os.path.exists("app.db"):
    os.remove("app.db")

from fastapi.testclient import TestClient
from main import app

c = TestClient(app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += cond; fail += (not cond)

# The FIRST account ever created is auto-admin (the site owner), so register a
# throwaway owner here to make the users below ordinary users.
c.post("/api/register", json={"email":"owner@test.com","password":"strongpass123"})

# frontend
r = c.get("/")
check("GET / serves frontend html", r.status_code == 200 and "SpeakUp" in r.text)

# register
r = c.post("/api/register", json={"email":"Haider@Test.com","password":"strongpass123"})
check("register returns token", r.status_code == 200 and "token" in r.json())
token = r.json().get("token","")
auth = {"Authorization": f"Bearer {token}"}

# duplicate register blocked
r = c.post("/api/register", json={"email":"haider@test.com","password":"strongpass123"})
check("duplicate email rejected", r.status_code == 400)

# weak password blocked
r = c.post("/api/register", json={"email":"new@test.com","password":"short"})
check("short password rejected", r.status_code == 400)

# login wrong password
r = c.post("/api/login", json={"email":"haider@test.com","password":"wrongpass99"})
check("wrong password rejected (401)", r.status_code == 401)

# login correct (email case-insensitive)
r = c.post("/api/login", json={"email":"HAIDER@test.com","password":"strongpass123"})
check("login works + case-insensitive email", r.status_code == 200 and "token" in r.json())

# no token blocked
r = c.get("/api/me")
check("me without token blocked (401)", r.status_code == 401)

# me with token
r = c.get("/api/me", headers=auth)
check("me returns user, not premium", r.status_code == 200 and r.json()["is_premium"] is False)

# lessons: premium locked for free user
r = c.get("/api/lessons", headers=auth)
ls = r.json()
premium = [l for l in ls if l["is_premium"]]
check("premium lessons locked + phrases hidden",
      all(l["locked"] and l["phrases"] == [] for l in premium))
free = [l for l in ls if not l["is_premium"]]
check("free lessons unlocked + phrases visible",
      all((not l["locked"]) and len(l["phrases"]) > 0 for l in free))

# cannot practice a locked premium lesson
r = c.post("/api/practice", headers=auth,
           json={"lesson_id":"interview","phrase_index":0,"score":90,"transcript":"x"})
check("practice on locked premium blocked (403)", r.status_code == 403)

# practice a free lesson
r = c.post("/api/practice", headers=auth,
           json={"lesson_id":"greetings","phrase_index":0,"score":88,"transcript":"hello nice to meet you"})
check("save practice on free lesson", r.status_code == 200 and r.json()["score"] == 88)

# score clamped to 0-100
r = c.post("/api/practice", headers=auth,
           json={"lesson_id":"greetings","phrase_index":1,"score":150,"transcript":"x"})
check("score clamped to 100", r.json()["score"] == 100)

# progress reflects attempts
r = c.get("/api/progress", headers=auth)
p = r.json()
check("progress counts attempts", p["total_attempts"] == 2 and p["best_by_lesson"].get("greetings") == 100)

# upgrade unlocks premium
r = c.post("/api/upgrade", headers=auth)
check("upgrade sets premium", r.json()["is_premium"] is True)

# now premium lessons unlocked
r = c.get("/api/lessons", headers=auth)
premium = [l for l in r.json() if l["is_premium"]]
check("after upgrade premium unlocked", all((not l["locked"]) and len(l["phrases"])>0 for l in premium))

# security headers present
r = c.get("/")
h = r.headers
check("security headers set",
      h.get("X-Frame-Options")=="DENY" and h.get("X-Content-Type-Options")=="nosniff")

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
