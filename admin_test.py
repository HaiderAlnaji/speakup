"""Tests for the admin panel. Run: python admin_test.py"""
import os
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["ADMIN_EMAIL"] = "boss@test.com"

from fastapi.testclient import TestClient
from main import app

c = TestClient(app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

# Security: there is NO "first user becomes admin" shortcut. On a public site
# that would hand your admin panel to the first stranger who signs up.
r = c.post("/api/register", json={"email":"owner@test.com","password":"strongpass123"})
check("first account is NOT auto-admin (security)", r.json()["user"]["is_admin"] is False)

# regular user is not admin
r = c.post("/api/register", json={"email":"normal@test.com","password":"strongpass123"})
normal_auth = {"Authorization": "Bearer " + r.json()["token"]}
check("normal user is not admin", r.json()["user"]["is_admin"] is False)

# admin-only routes blocked for normal user
r = c.get("/api/admin/users", headers=normal_auth)
check("normal user blocked from admin routes (403)", r.status_code == 403)

# the ADMIN_EMAIL account is auto-granted admin on register
r = c.post("/api/register", json={"email":"boss@test.com","password":"strongpass123"})
admin_auth = {"Authorization": "Bearer " + r.json()["token"]}
check("ADMIN_EMAIL account auto-granted admin", r.json()["user"]["is_admin"] is True)

# admin can list users
r = c.get("/api/admin/users", headers=admin_auth)
check("admin can list users", r.status_code == 200 and len(r.json()) == 3)

# admin can grant/remove premium for another user
users = r.json()
normal_id = [u for u in users if u["email"] == "normal@test.com"][0]["id"]
r = c.post(f"/api/admin/users/{normal_id}/toggle-premium", headers=admin_auth)
check("admin grants premium", r.json()["is_premium"] is True)
r = c.get("/api/me", headers=normal_auth)
check("normal user now sees premium", r.json()["is_premium"] is True)

# admin cannot delete themselves
r = c.get("/api/admin/users", headers=admin_auth)
admin_id = [u for u in r.json() if u["email"] == "boss@test.com"][0]["id"]
r = c.post(f"/api/admin/users/{admin_id}/delete", headers=admin_auth)
check("admin can't delete own account (400)", r.status_code == 400)

# admin unlocks all sprint days for themselves (admins already get Pro on register)
r = c.post("/api/admin/sprint/unlock-all", headers=admin_auth)
check("unlock-all works", r.status_code == 200 and r.json()["unlocked_through"] == 14)

# every day is now genuinely open with content (not just day 1)
r = c.get("/api/sprint", headers=admin_auth)
days = r.json()["days"]
check("all 14 days unlocked with content", all((not d["locked"]) and len(d["phrases"])>0 for d in days))

# but none are marked complete yet — admin still has to pass each one
check("no days pre-completed", r.json()["state"]["completed_days"] == [])

# admin can reset their own sprint
r = c.post("/api/admin/sprint/reset", headers=admin_auth)
check("reset works", r.status_code == 200)
r = c.get("/api/sprint", headers=admin_auth)
check("after reset, not enrolled", r.json()["state"]["enrolled"] is False)

# a non-admin, non-ADMIN_EMAIL user who registers later is never auto-admin
r = c.post("/api/register", json={"email":"another@test.com","password":"strongpass123"})
check("unrelated new user is not admin", r.json()["user"]["is_admin"] is False)

print(f"\n{ok} passed, {fail} failed")
os.remove("app.db")
