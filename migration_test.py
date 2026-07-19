"""Tests for auto-migration (self-healing schema). Run: python migration_test.py

This is a regression test for a real bug: an app.db created before new
columns were added to User crashed every login with
"no such column: user.paddle_customer_id". These tests prove that scenario
now self-heals automatically on startup, with zero data loss.
"""
import os, sys, subprocess, sqlite3, textwrap

ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

APP_DB = "app.db"
if os.path.exists(APP_DB):
    os.remove(APP_DB)

# ---- Recreate an OLD-schema database: exactly what existed before
#      paddle_customer_id / paddle_subscription_id / subscription_status
#      were added to the User model. ----
conn = sqlite3.connect(APP_DB)
conn.execute("""
    CREATE TABLE user (
        id INTEGER PRIMARY KEY,
        email VARCHAR NOT NULL UNIQUE,
        hashed_password VARCHAR NOT NULL,
        is_premium BOOLEAN NOT NULL,
        is_admin BOOLEAN NOT NULL,
        created_at DATETIME NOT NULL
    )
""")
conn.execute(
    "INSERT INTO user (email, hashed_password, is_premium, is_admin, created_at) "
    "VALUES (?, ?, 1, 0, datetime('now'))",
    ("old.user@test.com", "some-bcrypt-hash-that-must-survive"),
)
conn.commit()
conn.close()

# ---- Import main.py fresh in a SEPARATE process. This matters: if main.py
#      (and therefore the migration) were already imported earlier in this
#      test run against a different schema, Python's module cache would
#      skip re-running the migration and this test would prove nothing. ----
script = textwrap.dedent("""
    import main, json
    from sqlmodel import Session, select
    with Session(main.engine) as s:
        u = s.exec(select(main.User).where(main.User.email == "old.user@test.com")).first()
        print(json.dumps({
            "found": u is not None,
            "email": u.email if u else None,
            "hashed_password": u.hashed_password if u else None,
            "is_premium": u.is_premium if u else None,
            "subscription_status": u.subscription_status if u else None,
            "paddle_customer_id": u.paddle_customer_id if u else None,
        }))
""")
result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)

check("subprocess ran without crashing (this used to throw OperationalError)",
      result.returncode == 0)
check("startup banner reports the migration happened",
      "Migrated 'user'" in result.stdout and "paddle_customer_id" in result.stdout)

import json
# The JSON is the last line of stdout.
data_line = [l for l in result.stdout.strip().split("\n") if l.startswith("{")]
check("subprocess printed its result", len(data_line) == 1)
if data_line:
    data = json.loads(data_line[0])
    check("the pre-existing user still exists after migration", data["found"] is True)
    check("email was preserved exactly", data["email"] == "old.user@test.com")
    check("password hash was preserved exactly (not reset)",
          data["hashed_password"] == "some-bcrypt-hash-that-must-survive")
    check("is_premium (pre-existing data) was preserved as True",
          data["is_premium"] is True)
    check("new column subscription_status defaulted sensibly to 'none'",
          data["subscription_status"] == "none")
    check("new nullable column paddle_customer_id defaulted to None",
          data["paddle_customer_id"] is None)

# ---- Idempotency: running it again must be a silent no-op, not an error ----
result2 = subprocess.run([sys.executable, "-c", "import main"], capture_output=True, text=True)
check("running migration again (already-migrated DB) doesn't crash",
      result2.returncode == 0)
check("second run does NOT re-report the migration (already done, no-op)",
      "Migrated 'user'" not in result2.stdout)

# ---- A real login against the healed database actually works now ----
login_script = textwrap.dedent("""
    import main, bcrypt
    from sqlmodel import Session, select
    # give the pre-existing user a real bcrypt hash so login can succeed
    with Session(main.engine) as s:
        u = s.exec(select(main.User).where(main.User.email == "old.user@test.com")).first()
        u.hashed_password = bcrypt.hashpw(b"strongpass123", bcrypt.gensalt()).decode()
        s.add(u); s.commit()
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    r = c.post("/api/login", json={"email": "old.user@test.com", "password": "strongpass123"})
    print(r.status_code)
""")
result3 = subprocess.run([sys.executable, "-c", login_script], capture_output=True, text=True)
check("login against the self-healed database succeeds (this is the actual bug, fixed)",
      result3.stdout.strip().endswith("200"))

print(f"\n{ok} passed, {fail} failed")
if os.path.exists(APP_DB):
    os.remove(APP_DB)
