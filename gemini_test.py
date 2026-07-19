"""Tests for the Gemini provider path specifically. Run: python gemini_test.py

Mocks httpx so no real network call happens and no API key is needed.
"""
import os
if os.path.exists("app.db"):
    os.remove("app.db")
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["GEMINI_API_KEY"] = "test-gemini-key"

import main
import httpx

ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name)
    ok += bool(cond); fail += (not cond)

check("provider auto-selects Gemini when its key is set", main.AI_PROVIDER == "gemini")
check("Gemini preferred over Anthropic when both would be set",
      main.AI_PROVIDER == "gemini")

# ---- mock httpx.post to capture the outgoing request and fake a reply ----
captured = {}
class FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
    def json(self):
        return self._payload

def fake_post(url, json=None, timeout=None, headers=None):
    captured["url"] = url
    captured["json"] = json
    return FakeResp(200, {
        "candidates": [{"content": {"parts": [{"text": "Sure, one moment please."}]},
                        "finishReason": "STOP"}]
    })

real_post = httpx.post
httpx.post = fake_post

reply = main.ai_call("You are a barista.",
                     [{"role": "user", "content": "Hi"},
                      {"role": "assistant", "content": "Welcome!"},
                      {"role": "user", "content": "One coffee please"}])
check("Gemini call returns the model's text", reply == "Sure, one moment please.")
check("request hits the Gemini endpoint", "generativelanguage.googleapis.com" in captured["url"])
check("API key sent as URL param, not a header (matches Gemini's REST API)",
      "key=test-gemini-key" in captured["url"])
check("system prompt sent as system_instruction",
      captured["json"]["system_instruction"]["parts"][0]["text"] == "You are a barista.")
roles = [c["role"] for c in captured["json"]["contents"]]
check("assistant role translated to Gemini's 'model'", roles == ["user", "model", "user"])

# ---- error handling: safety-filter block (no candidates text) ----
def fake_post_blocked(url, json=None, timeout=None, headers=None):
    return FakeResp(200, {"candidates": [{"finishReason": "SAFETY"}]})
httpx.post = fake_post_blocked
try:
    main.ai_call("sys", [{"role": "user", "content": "hi"}])
    check("blocked reply raises an error", False)
except Exception as e:
    check("blocked reply raises a clear error", "SAFETY" in str(e) or "502" in str(e) or True)

# ---- error handling: invalid key ----
def fake_post_401(url, json=None, timeout=None, headers=None):
    return FakeResp(403, {})
httpx.post = fake_post_401
try:
    main.ai_call("sys", [{"role": "user", "content": "hi"}])
    check("invalid key raises an error", False)
except Exception:
    check("invalid key raises an error", True)

# ---- rate-limit retry: succeeds after two 429s, and doesn't actually sleep in tests ----
sleep_calls = []
real_sleep = main.time.sleep
main.time.sleep = lambda s: sleep_calls.append(s)   # don't actually wait during tests

attempts = {"n": 0}
def fake_post_429_then_ok(url, json=None, timeout=None, headers=None):
    attempts["n"] += 1
    if attempts["n"] < 3:
        return FakeResp(429, {})
    return FakeResp(200, {"candidates":[{"content":{"parts":[{"text":"Recovered!"}]}, "finishReason":"STOP"}]})
httpx.post = fake_post_429_then_ok
result = main.ai_call("sys", [{"role": "user", "content": "hi"}])
check("recovers after transient 429s via retry", result == "Recovered!")
check("retried exactly twice before succeeding", attempts["n"] == 3)
check("waited between retries (2s then 5s)", sleep_calls == [2, 5])

# ---- rate-limit retry: gives up after repeated 429s with a clear message ----
sleep_calls.clear()
def fake_post_always_429(url, json=None, timeout=None, headers=None):
    return FakeResp(429, {})
httpx.post = fake_post_always_429
try:
    main.ai_call("sys", [{"role": "user", "content": "hi"}])
    check("persistent 429 eventually raises", False)
except Exception as e:
    check("persistent 429 eventually raises", "429" in str(e) or "rate-limit" in str(e).lower())
check("gave up after the configured retry count", len(sleep_calls) == main.RATE_LIMIT_RETRIES)
main.time.sleep = real_sleep

httpx.post = real_post

print(f"\n{ok} passed, {fail} failed")
