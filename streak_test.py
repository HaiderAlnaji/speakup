"""Tests for the daily practice streak. Run: python streak_test.py"""
import os, datetime as dt
if os.path.exists("app.db"):
    os.remove("app.db")

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from main import engine, Attempt, User

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

def seed(email, day_offsets):
    """Create a user and give them an attempt on each of the given day-offsets."""
    r = c.post("/api/register", json={"email": email, "password": "strongpass123"})
    auth = {"Authorization": "Bearer " + r.json()["token"]}
    with Session(engine) as s:
        u = s.exec(select(User).where(User.email == email)).first()
        now = dt.datetime.utcnow()
        for d in day_offsets:
            s.add(Attempt(user_id=u.id, lesson_id="x", phrase_index=0, score=80,
                          created_at=now - dt.timedelta(days=d)))
        s.commit()
    return auth

# brand-new user: no streak
r = c.post("/api/register", json={"email": "new@t.com", "password": "strongpass123"})
p = c.get("/api/progress", headers={"Authorization": "Bearer " + r.json()["token"]}).json()
check("new user has 0 streak", p["streak"] == 0)
check("new user has not practiced today", p["practiced_today"] is False)

# practiced today, yesterday, day before => 3-day streak
auth = seed("three@t.com", [0, 1, 2])
p = c.get("/api/progress", headers=auth).json()
check("3 consecutive days => streak 3", p["streak"] == 3)
check("practiced today is True", p["practiced_today"] is True)

# a gap breaks the streak
auth = seed("gap@t.com", [0, 1, 4, 5])
p = c.get("/api/progress", headers=auth).json()
check("gap breaks current streak (today+yesterday = 2)", p["streak"] == 2)
check("longest streak spans the earlier run too", p["longest_streak"] == 2)
check("days practiced counts all active days", p["days_practiced"] == 4)

# streak stays alive if they practised yesterday but not yet today
auth = seed("yesterday@t.com", [1, 2, 3])
p = c.get("/api/progress", headers=auth).json()
check("streak survives if last practice was yesterday", p["streak"] == 3)
check("but practiced_today is False (nudges them to keep it)", p["practiced_today"] is False)

# streak is dead if last practice was 2+ days ago
auth = seed("stale@t.com", [3, 4, 5])
p = c.get("/api/progress", headers=auth).json()
check("streak resets if last practice was 2+ days ago", p["streak"] == 0)



# ---- progress history graph is Pro-gated ----
# Insert this user straight into the DB rather than through /api/register —
# this test file already registers 5 accounts above (the app's real 5/60s
# registration limit), and going through the endpoint again would trip it.
# This is a test-setup shortcut only; the limiter itself is unchanged.
from main import hash_password, create_token
with Session(engine) as s:
    hist_user = User(email="history@t.com", hashed_password=hash_password("strongpass123"),
                     is_premium=False)
    s.add(hist_user); s.commit(); s.refresh(hist_user)
    hist_token = create_token(hist_user.id)
history_auth = {"Authorization": "Bearer " + hist_token}

r = c.get("/api/progress/history", headers=history_auth)
check("progress history blocked for free user (403)", r.status_code == 403)

c.post("/api/upgrade", headers=history_auth)
with Session(engine) as s:
    u = s.exec(select(User).where(User.email == "history@t.com")).first()
    now = dt.datetime.utcnow()
    for d, sc in [(0, 90), (0, 80), (1, 70), (2, 60), (3, 50)]:
        s.add(Attempt(user_id=u.id, lesson_id="x", phrase_index=0, score=sc,
                      created_at=now - dt.timedelta(days=d)))
    s.commit()
r = c.get("/api/progress/history", headers=history_auth)
body = r.json()
check("Pro user gets progress history (200)", r.status_code == 200)
check("history has one point per active day", len(body["points"]) == 4)
today_point = [p for p in body["points"] if p["attempts"] == 2][0]
check("multiple same-day attempts are averaged", today_point["avg_score"] == 85)
check("trend field present", body["trend"] in ("improving","declining","steady"))
# Chronologically: 3 days ago=50, 2 days ago=60, yesterday=70, today=avg(90,80)=85.
# Scores rise over time, so this is correctly detected as "improving".
check("rising scores over days detected as 'improving' trend", body["trend"] == "improving")

# ---- and the reverse case: scores genuinely falling over time ----
with Session(engine) as s:
    fall_user = User(email="falling@t.com", hashed_password=hash_password("strongpass123"),
                     is_premium=True)
    s.add(fall_user); s.commit(); s.refresh(fall_user)
    fall_token = create_token(fall_user.id)
    now = dt.datetime.utcnow()
    # chronologically oldest -> newest: 3 days ago=90, 2 days ago=80, yesterday=60, today=40
    for d, sc in [(3, 90), (2, 80), (1, 60), (0, 40)]:
        s.add(Attempt(user_id=fall_user.id, lesson_id="x", phrase_index=0, score=sc,
                      created_at=now - dt.timedelta(days=d)))
    s.commit()
r = c.get("/api/progress/history", headers={"Authorization": "Bearer " + fall_token})
check("falling scores over days detected as 'declining' trend", r.json()["trend"] == "declining")

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
