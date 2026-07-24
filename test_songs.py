"""Tests for the Songs feature: AI-original songs (Gemini), real-song
lookup (Musixmatch), and the connected-speech breakdown (Gemini). All
Max-only.

Focus: require_max rejects free/Pro users before any external call is
made; requests sent to Gemini/Musixmatch have the right shape; the parsers
handle realistic responses AND malformed/restricted ones without crashing.
requests.post/.get are faked throughout -- no real network call, no real
API keys needed to run this.

Run: python test_songs.py
"""
import os
if os.path.exists("app.db"):
    os.remove("app.db")

os.environ["GEMINI_API_KEY"] = "test_gemini_key"
os.environ["MUSIXMATCH_API_KEY"] = "test_musixmatch_key"

import main
from fastapi.testclient import TestClient
from sqlmodel import Session, select

c = TestClient(main.app)
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)


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
        song = {"title": "Rainy Monday", "lines": [
            "Rain is falling on my street",
            "I put my boots on both my feet",
            "Monday morning, here we go",
            "Rain is falling, soft and slow",
        ]}
        return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(song)}]}}]})
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
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"})
check("no auth -> 401", r.status_code == 401)

# ---- free user ----
free_id, free_auth = new_user("songs_free@test.com")
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=free_auth)
check("free user -> 403 (Max only)", r.status_code == 403)

# ---- pro (not max) user ----
pro_id, pro_auth = new_user("songs_pro@test.com")
set_tier(pro_id, True, "pro")
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=pro_auth)
check("pro (non-max) user -> 403 (Max only)", r.status_code == 403)

# ---- max user, real generate path ----
max_id, max_auth = new_user("songs_max@test.com")
set_tier(max_id, True, "max")

r = c.post("/api/songs/generate", json={"theme": "rainy Mondays", "level": "Intermediate"}, headers=max_auth)
check("max user -> 200", r.status_code == 200)
body = r.json()
check("response has a title", body.get("title") == "Rainy Monday")
check("response has lines list", body.get("lines") == [
    "Rain is falling on my street", "I put my boots on both my feet",
    "Monday morning, here we go", "Rain is falling, soft and slow",
])
check("theme reached the system_instruction", "rainy Mondays" in _last_request["json"]["system_instruction"]["parts"][0]["text"])
check("level reached the system_instruction", "Intermediate" in _last_request["json"]["system_instruction"]["parts"][0]["text"])
check("API key sent as query param, not in body", _last_request["params"] == {"key": "test_gemini_key"})
check("requests structured JSON output from Gemini", _last_request["json"]["generationConfig"]["responseMimeType"] == "application/json")
check("provides a responseSchema", "responseSchema" in _last_request["json"]["generationConfig"])

# ---- invalid level silently falls back to Beginner instead of erroring ----
_last_request.clear()
r = c.post("/api/songs/generate", json={"theme": "space", "level": "Expert"}, headers=max_auth)
check("invalid level -> 200 (falls back to Beginner)", r.status_code == 200)
check("Beginner reached the system_instruction as the fallback", "Beginner" in _last_request["json"]["system_instruction"]["parts"][0]["text"])

# ---- blank theme is allowed (falls back to a generic topic clause) ----
r = c.post("/api/songs/generate", json={"theme": "", "level": "Beginner"}, headers=max_auth)
check("blank theme -> 200, not rejected", r.status_code == 200)

# ---- Gemini returns malformed JSON -> 502, not a 500 crash ----
def fake_post_bad_json(url, **kwargs):
    return FakeResp({"candidates": [{"content": {"parts": [{"text": "not valid json at all"}]}}]})
main.requests.post = fake_post_bad_json
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=max_auth)
check("malformed JSON from Gemini -> 502, not a 500", r.status_code == 502)

# ---- Gemini wraps JSON in a markdown fence -- still parses ----
def fake_post_fenced(url, **kwargs):
    song = {"title": "Fenced Song", "lines": ["Line one here", "Line two here"]}
    text = "```json\n" + main._json.dumps(song) + "\n```"
    return FakeResp({"candidates": [{"content": {"parts": [{"text": text}]}}]})
main.requests.post = fake_post_fenced
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=max_auth)
check("markdown-fenced JSON still parses -> 200", r.status_code == 200)
check("title parsed correctly through the fence", r.json().get("title") == "Fenced Song")

# ---- Gemini safety-block / empty candidates handled gracefully ----
def fake_post_blocked(url, **kwargs):
    return FakeResp({"candidates": [{"finishReason": "SAFETY"}]})
main.requests.post = fake_post_blocked
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=max_auth)
check("safety-blocked Gemini response -> 502, not a 500 crash", r.status_code == 502)

# ---- Gemini HTTP error surfaced, not swallowed ----
def fake_post_error(url, **kwargs):
    return FakeResp({}, ok=False, status_code=429, text="rate limited")
main.requests.post = fake_post_error
r = c.post("/api/songs/generate", json={"theme": "rain", "level": "Beginner"}, headers=max_auth)
check("Gemini HTTP error -> 502 with detail", r.status_code == 502 and "429" in r.json()["detail"])

# ============================================================
#  /api/songs/search-real -- real lyrics via Musixmatch (Max only).
#  Gemini is never the lyrics source here; requests.get is faked separately
#  from requests.post above.
# ============================================================
check("MUSIXMATCH_CONFIGURED is True once MUSIXMATCH_API_KEY is set", main.MUSIXMATCH_CONFIGURED is True)

_last_get = {}
def fake_get_musixmatch(url, **kwargs):
    _last_get["url"] = url
    _last_get["params"] = kwargs.get("params")
    return FakeResp({"message": {"header": {"status_code": 200}, "body": {"lyrics": {
        "lyrics_body": "Line one of the song\nLine two of the song\nLine three chorus\n\n*******\nThis Lyrics is NOT for Commercial use\n*******\n(1409192424111)",
        "lyrics_copyright": "Writer: Someone. Lyrics powered by www.musixmatch.com",
    }}}})
main.requests.get = fake_get_musixmatch

r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": "Test Artist"})
check("no auth -> 401", r.status_code == 401)

r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": "Test Artist"}, headers=free_auth)
check("free user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": "Test Artist"}, headers=pro_auth)
check("pro (non-max) user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": "Test Artist"}, headers=max_auth)
check("max user -> 200", r.status_code == 200)
body = r.json()
check("lines parsed, boilerplate stripped", body.get("lines") == ["Line one of the song", "Line two of the song", "Line three chorus"])
check("restricted=True when free-tier boilerplate is present", body.get("restricted") is True)
check("track/artist sent as query params to Musixmatch, not in a body", _last_get["params"] == {"q_track": "Test Song", "q_artist": "Test Artist", "apikey": "test_musixmatch_key", "format": "json"})

r = c.post("/api/songs/search-real", json={"track": "", "artist": ""}, headers=max_auth)
check("blank track -> 400", r.status_code == 400)

def fake_get_not_found(url, **kwargs):
    return FakeResp({"message": {"header": {"status_code": 404}, "body": {}}})
main.requests.get = fake_get_not_found
r = c.post("/api/songs/search-real", json={"track": "Nonexistent Song XYZ", "artist": ""}, headers=max_auth)
check("Musixmatch no-match (404) -> 404, not a 500", r.status_code == 404)

def fake_get_bad_key(url, **kwargs):
    return FakeResp({"message": {"header": {"status_code": 401}, "body": {}}})
main.requests.get = fake_get_bad_key
r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": ""}, headers=max_auth)
check("Musixmatch bad-key (401) -> 502, not a 500", r.status_code == 502)

def fake_get_quota(url, **kwargs):
    return FakeResp({"message": {"header": {"status_code": 402}, "body": {}}})
main.requests.get = fake_get_quota
r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": ""}, headers=max_auth)
check("Musixmatch quota exceeded (402) -> 502, not a 500", r.status_code == 502)

def fake_get_http_error(url, **kwargs):
    return FakeResp({}, ok=False, status_code=500, text="server error")
main.requests.get = fake_get_http_error
r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": ""}, headers=max_auth)
check("Musixmatch HTTP error -> 502, not a 500", r.status_code == 502)

# ---- Musixmatch not configured on the server ----
main.MUSIXMATCH_CONFIGURED = False
main.requests.get = fake_get_musixmatch
r = c.post("/api/songs/search-real", json={"track": "Test Song", "artist": ""}, headers=max_auth)
check("Musixmatch not configured -> 503", r.status_code == 503)
main.MUSIXMATCH_CONFIGURED = True   # restore for any tests after this point

# ============================================================
#  /api/songs/breakdown -- connected-speech breakdown (Max only).
# ============================================================
def fake_post_breakdown(url, **kwargs):
    bd = {"literal": "it was not me", "linking": "it_wasn't_me", "reduced": "it ain't me", "fluent": "it ain(t) me"}
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(bd)}]}}]})
main.requests.post = fake_post_breakdown

r = c.post("/api/songs/breakdown", json={"text": "it was not me"})
check("no auth -> 401", r.status_code == 401)

r = c.post("/api/songs/breakdown", json={"text": "it was not me"}, headers=free_auth)
check("free user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/breakdown", json={"text": "it was not me"}, headers=max_auth)
check("max user -> 200", r.status_code == 200)
check("all 4 layers present and correct", r.json() == {
    "literal": "it was not me", "linking": "it_wasn't_me",
    "reduced": "it ain't me", "fluent": "it ain(t) me",
})

r = c.post("/api/songs/breakdown", json={"text": "   "}, headers=max_auth)
check("blank text -> 400", r.status_code == 400)

def fake_post_breakdown_bad_json(url, **kwargs):
    return FakeResp({"candidates": [{"content": {"parts": [{"text": "not json"}]}}]})
main.requests.post = fake_post_breakdown_bad_json
r = c.post("/api/songs/breakdown", json={"text": "it was not me"}, headers=max_auth)
check("malformed breakdown JSON -> 502, not a 500", r.status_code == 502)

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"):
    os.remove("app.db")
