"""Tests for the Songs feature's Gemini-backed pronunciation tools (all
Max-only): the connected-speech breakdown (now with an IPA transcription
per layer), the batch version of it, and single-word lookup (stress, IPA,
definition). Practicing with a real song itself (pasting a YouTube link,
embedding YouTube's own player, typing a line to score) is 100%
client-side -- no lyrics database, no server endpoint, nothing to test
here with a backend test.

Focus: require_max rejects free/Pro users before any external call is
made; requests sent to Gemini have the right shape; the parsers handle
realistic responses AND malformed ones without crashing. requests.post
is faked throughout -- no real network call, no real API key needed to
run this.

Run: python test_songs.py
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


class FakeResp:
    def __init__(self, json_body, ok=True, status_code=200, text=""):
        self._json = json_body; self.ok = ok; self.status_code = status_code
        self.text = text or str(json_body)
    def json(self): return self._json


def fake_breakdown_json(prefix="example line"):
    return {
        "literal": f"{prefix} literal", "literal_ipa": "/ɪɡˈzæmpəl/",
        "linking": f"{prefix} linking", "linking_ipa": "/ɪɡˈzæmpəl/",
        "reduced": f"{prefix} reduced", "reduced_ipa": "/ɪɡˈzæmpəl/",
        "fluent": f"{prefix} fluent", "fluent_ipa": "/ɪɡˈzæmpəl/",
    }


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

free_id, free_auth = new_user("songs_free@test.com")
pro_id, pro_auth = new_user("songs_pro@test.com")
set_tier(pro_id, True, "pro")
max_id, max_auth = new_user("songs_max@test.com")
set_tier(max_id, True, "max")

# ============================================================
#  /api/songs/breakdown -- connected-speech breakdown (Max only).
# ============================================================
_last_request = {}
def fake_post_breakdown(url, **kwargs):
    _last_request["url"] = url
    _last_request["json"] = kwargs.get("json")
    _last_request["params"] = kwargs.get("params")
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(fake_breakdown_json())}]}}]})
main.requests.post = fake_post_breakdown

r = c.post("/api/songs/breakdown", json={"text": "example line"})
check("no auth -> 401", r.status_code == 401)

r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=free_auth)
check("free user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=pro_auth)
check("pro (non-max) user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=max_auth)
check("max user -> 200", r.status_code == 200)
check("all 4 layers present and correct", r.json() == fake_breakdown_json())
check("an IPA field accompanies each layer", all(k in r.json() for k in ("literal_ipa", "linking_ipa", "reduced_ipa", "fluent_ipa")))
check("text reached Gemini in the user turn", "example line" in _last_request["json"]["contents"][0]["parts"][0]["text"])
check("API key sent as query param, not in body", _last_request["params"] == {"key": "test_gemini_key"})
check("requests structured JSON output from Gemini", _last_request["json"]["generationConfig"]["responseMimeType"] == "application/json")
check("provides a responseSchema", "responseSchema" in _last_request["json"]["generationConfig"])
check("responseSchema requires all 8 fields (4 layers + 4 IPA)", len(_last_request["json"]["generationConfig"]["responseSchema"]["required"]) == 8)

r = c.post("/api/songs/breakdown", json={"text": "   "}, headers=max_auth)
check("blank text -> 400", r.status_code == 400)

def fake_post_breakdown_bad_json(url, **kwargs):
    return FakeResp({"candidates": [{"content": {"parts": [{"text": "not json"}]}}]})
main.requests.post = fake_post_breakdown_bad_json
r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=max_auth)
check("malformed breakdown JSON -> 502, not a 500", r.status_code == 502)

def fake_post_breakdown_missing_ipa(url, **kwargs):
    bd = {"literal": "x", "linking": "x", "reduced": "x", "fluent": "x"}  # old shape, no IPA
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(bd)}]}}]})
main.requests.post = fake_post_breakdown_missing_ipa
r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=max_auth)
check("response missing the new IPA fields -> 502, not a 500", r.status_code == 502)

def fake_post_blocked(url, **kwargs):
    return FakeResp({"candidates": [{"finishReason": "SAFETY"}]})
main.requests.post = fake_post_blocked
r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=max_auth)
check("safety-blocked Gemini response -> 502, not a 500 crash", r.status_code == 502)

def fake_post_error(url, **kwargs):
    return FakeResp({}, ok=False, status_code=429, text="rate limited")
main.requests.post = fake_post_error
r = c.post("/api/songs/breakdown", json={"text": "example line"}, headers=max_auth)
check("Gemini HTTP error -> 502 with detail", r.status_code == 502 and "429" in r.json()["detail"])

# ============================================================
#  /api/songs/breakdown-batch -- several typed-in lines at once (Max only).
# ============================================================
main.requests.post = lambda url, **kw: FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(fake_breakdown_json())}]}}]})

r = c.post("/api/songs/breakdown-batch", json={"lines": ["example line one", "example line two"]})
check("batch: no auth -> 401", r.status_code == 401)

r = c.post("/api/songs/breakdown-batch", json={"lines": ["example line one"]}, headers=free_auth)
check("batch: free user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/breakdown-batch", json={"lines": ["example line one", "example line two", ""]}, headers=max_auth)
check("batch: max user -> 200", r.status_code == 200)
body = r.json()
check("batch: blank line filtered out, 2 lines returned", body["lines"] == ["example line one", "example line two"])
check("batch: 2 results returned, both ok", len(body["results"]) == 2 and all(x["ok"] for x in body["results"]))
check("batch: each result has all 4 layers + IPA", body["results"][0]["literal_ipa"] == "/ɪɡˈzæmpəl/")

r = c.post("/api/songs/breakdown-batch", json={"lines": [f"line {i}" for i in range(20)]}, headers=max_auth)
check("batch: capped at 8 lines even if more are sent", len(r.json()["lines"]) == 8)

r = c.post("/api/songs/breakdown-batch", json={"lines": ["   ", ""]}, headers=max_auth)
check("batch: all-blank lines -> 400", r.status_code == 400)

r = c.post("/api/songs/breakdown-batch", json={"lines": []}, headers=max_auth)
check("batch: empty list -> 400", r.status_code == 400)

# ---- one bad line doesn't fail the whole batch ----
_call_n = {"n": 0}
def fake_post_batch_partial_fail(url, **kwargs):
    _call_n["n"] += 1
    if _call_n["n"] == 2:
        return FakeResp({"candidates": [{"content": {"parts": [{"text": "not json"}]}}]})
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(fake_breakdown_json())}]}}]})
main.requests.post = fake_post_batch_partial_fail
r = c.post("/api/songs/breakdown-batch", json={"lines": ["line a", "line b", "line c"]}, headers=max_auth)
check("batch: partial failure -> still 200 overall", r.status_code == 200)
results = r.json()["results"]
check("batch: line 1 ok, line 2 failed, line 3 ok", results[0]["ok"] is True and results[1]["ok"] is False and results[2]["ok"] is True)
check("batch: failed line carries an error message", "error" in results[1])

# ============================================================
#  /api/songs/word-lookup -- single-word stress + IPA + definition (Max only).
# ============================================================
_last_word_request = {}
def fake_post_word(url, **kwargs):
    _last_word_request["json"] = kwargs.get("json")
    wl = {"word": "example", "syllables": ["ex", "am", "ple"], "stressed_index": 0,
          "ipa": "/ˈɛɡ zæm pəl/", "definition": "a thing that shows what something is like"}
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(wl)}]}}]})
main.requests.post = fake_post_word

r = c.post("/api/songs/word-lookup", json={"word": "example"})
check("word-lookup: no auth -> 401", r.status_code == 401)

r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=free_auth)
check("word-lookup: free user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=pro_auth)
check("word-lookup: pro (non-max) user -> 403 (Max only)", r.status_code == 403)

r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=max_auth)
check("word-lookup: max user -> 200", r.status_code == 200)
body = r.json()
check("word-lookup: word/syllables/ipa/definition present", body["word"] == "example" and body["syllables"] == ["ex", "am", "ple"] and body["ipa"] and body["definition"])
check("word-lookup: stressed_index in range", body["stressed_index"] == 0)
check("word reached Gemini in the user turn", "example" in _last_word_request["json"]["contents"][0]["parts"][0]["text"])

r = c.post("/api/songs/word-lookup", json={"word": "   "}, headers=max_auth)
check("word-lookup: blank word -> 400", r.status_code == 400)

def fake_post_word_bad_index(url, **kwargs):
    wl = {"word": "example", "syllables": ["ex", "am", "ple"], "stressed_index": 99,
          "ipa": "/ˈɛɡ zæm pəl/", "definition": "a thing that shows what something is like"}
    return FakeResp({"candidates": [{"content": {"parts": [{"text": main._json.dumps(wl)}]}}]})
main.requests.post = fake_post_word_bad_index
r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=max_auth)
check("word-lookup: out-of-range stressed_index falls back to 0, not a crash", r.status_code == 200 and r.json()["stressed_index"] == 0)

def fake_post_word_bad_json(url, **kwargs):
    return FakeResp({"candidates": [{"content": {"parts": [{"text": "not json"}]}}]})
main.requests.post = fake_post_word_bad_json
r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=max_auth)
check("word-lookup: malformed JSON -> 502, not a 500", r.status_code == 502)

def fake_post_word_error(url, **kwargs):
    return FakeResp({}, ok=False, status_code=429, text="rate limited")
main.requests.post = fake_post_word_error
r = c.post("/api/songs/word-lookup", json={"word": "example"}, headers=max_auth)
check("word-lookup: Gemini HTTP error -> 502 with detail", r.status_code == 502 and "429" in r.json()["detail"])

print(f"\n{ok} passed, {fail} failed")
if os.path.exists("app.db"):
    os.remove("app.db")
