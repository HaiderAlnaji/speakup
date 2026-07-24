"""
SpeakPort — English speaking practice app (backend + serves the frontend)

One file so it's easy to read top to bottom.
Sections:
  1. Config
  2. Database (SQLite)
  3. Lessons (the learning content)
  4. Security helpers (password hashing + JWT tokens)
  5. A simple rate limiter (basic brute-force protection)
  6. Request/response shapes
  7. Routes (the API)
  8. Serve the frontend + security headers

Run it with:  uvicorn main:app --reload
Then open:     http://localhost:8000
"""

import os
import hmac
import hashlib
import json as _json
import random
import re
import secrets
import smtplib
import time
import uuid
import datetime as dt
from email.message import EmailMessage
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv

# Load .env from THIS file's folder, no matter which directory you run from.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

import jwt  # PyJWT
import bcrypt
import requests
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, Response, RedirectResponse, HTMLResponse
from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy import inspect as sa_inspect, text as sa_text
from pydantic import BaseModel


# ----------------------------------------------------------------------
# 1. CONFIG
# ----------------------------------------------------------------------
# SECRET_KEY signs the login tokens. In production this MUST come from an
# environment variable and be long and random. The dev default below is only
# so the app runs out of the box on your machine.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me-in-production")
ALGORITHM = "HS256"
TOKEN_HOURS = 24 * 7  # how long a login stays valid

# Whichever email is set here IS an admin — checked live on every request, so
# you never have to worry about a stale flag saved in the database.
# Admins are defined ONLY here — the single source of truth. Put one email,
# or several separated by commas, e.g.  ADMIN_EMAIL=me@x.com,partner@x.com
# Anyone whose email is NOT in this list is guaranteed to be a non-admin on
# every request, no matter what's stored in the database. This is what makes
# it impossible for a stray/old flag to grant someone admin.
ADMIN_EMAILS = {e.strip().lower() for e in os.getenv("ADMIN_EMAIL", "").split(",") if e.strip()}

# Contact address shown on the legal pages (Terms/Privacy/Refund). Falls back
# to your first ADMIN_EMAIL so you don't have to set anything extra to get
# started — set SUPPORT_EMAIL explicitly once you have a dedicated address.
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "").strip() or (sorted(ADMIN_EMAILS)[0] if ADMIN_EMAILS else "support@example.com")

# ----------------------------------------------------------------------
# 1c-2. EMAIL — for "forgot password" reset links
# ----------------------------------------------------------------------
# Uses plain SMTP (Python's built-in smtplib, no extra package to install).
# Any SMTP account works: a Gmail address with an "app password"
# (myaccount.google.com/apppasswords), Zoho, Outlook, or the SMTP relay of
# a transactional service like Resend/Mailgun/SendGrid's free tier.
#   SMTP_HOST=smtp.gmail.com
#   SMTP_PORT=587
#   SMTP_USERNAME=you@gmail.com
#   SMTP_PASSWORD=your-16-char-app-password
#   SMTP_FROM=you@gmail.com                 (optional, defaults to SMTP_USERNAME)
# Until these are set, SpeakPort runs in DEMO MODE for password resets: instead
# of emailing a link, /api/forgot-password hands the reset link straight back
# in its response so you can still test (and use) the flow before setting up
# real email sending.
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "").strip() or SMTP_USERNAME
EMAIL_CONFIGURED = bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD)

# Used to build the absolute reset link in the email (e.g.
# https://speakport-h4k8.onrender.com). Falls back to a same-origin relative
# link if unset, which still works fine for the demo-mode response.
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")

# ----------------------------------------------------------------------
# 1c-3. GOOGLE SIGN-IN — one-click registration/login as an alternative to
# typing an email + password
# ----------------------------------------------------------------------
# Unlike every other credential in this file, a Client ID is NOT a secret —
# Google's own docs say it's safe to ship in public frontend code (it just
# identifies which app is asking, the same way a Stripe "publishable key"
# does). So there's no password/API-secret step here at all: create one
# free at console.cloud.google.com/apis/credentials -> "Create Credentials"
# -> "OAuth client ID" -> Application type "Web application" -> add your
# site's URL under "Authorized JavaScript origins".
#
# Until GOOGLE_CLIENT_ID is set, the "Sign in with Google" button simply
# doesn't render — same demo-mode-until-configured pattern as every payment
# provider below.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CONFIGURED = bool(GOOGLE_CLIENT_ID)

# Google's public keys, used to verify the signature on every Google sign-in
# token. PyJWT fetches + caches these automatically over its lifetime — no
# extra dependency, since PyJWT is already used above for our own login
# tokens (see create_token in section 4).
_google_jwks_client = jwt.PyJWKClient("https://www.googleapis.com/oauth2/v3/certs") if GOOGLE_CONFIGURED else None

# ----------------------------------------------------------------------
# 1d. PAYMENTS — Paddle (Merchant of Record; supports payout via Payoneer,
# which works in countries Stripe doesn't, including Iraq)
# ----------------------------------------------------------------------
# Paddle handles the actual card charging, sales tax, and compliance for you.
# You never see or touch a card number — Paddle sends your server a signed
# webhook after a real payment, and ONLY that webhook may grant Pro.
#
# Get these from paddle.com -> Developer Tools -> Authentication:
PADDLE_API_KEY = os.getenv("PADDLE_API_KEY", "").strip()            # server-side, secret
PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()  # secret, verifies webhooks
PADDLE_CLIENT_TOKEN = os.getenv("PADDLE_CLIENT_TOKEN", "").strip()  # public, safe for the browser
PADDLE_PRICE_ID = os.getenv("PADDLE_PRICE_ID", "").strip()          # the $4.99/mo Pro price
# Optional: a SECOND Paddle Price for annual billing (create it yourself in
# the Paddle dashboard -- Paddle handles the recurring yearly charge exactly
# like the monthly one, just on a different billing interval). Annual
# checkout is only offered to Paddle customers once this is set; until
# then they still get the monthly price, same as before this existed.
PADDLE_PRICE_ID_ANNUAL = os.getenv("PADDLE_PRICE_ID_ANNUAL", "").strip()
# Optional: the Max tier's Paddle Prices (Pro + AI Roleplay). Same idea as
# above -- create these yourself in the Paddle dashboard. Max checkout is
# only offered to Paddle customers once at least the monthly one is set.
PADDLE_PRICE_ID_MAX = os.getenv("PADDLE_PRICE_ID_MAX", "").strip()
PADDLE_PRICE_ID_MAX_ANNUAL = os.getenv("PADDLE_PRICE_ID_MAX_ANNUAL", "").strip()
PADDLE_ENV = os.getenv("PADDLE_ENV", "sandbox").strip()             # "sandbox" or "production"

# All four must be set for real payments to be live. Until then, SpeakPort
# stays in demo mode: /api/upgrade instantly grants Pro so you can test
# everything locally without a Paddle account. The moment real credentials
# are set (in production), that shortcut automatically closes — see /api/upgrade.
PADDLE_CONFIGURED = bool(PADDLE_API_KEY and PADDLE_WEBHOOK_SECRET
                         and PADDLE_CLIENT_TOKEN and PADDLE_PRICE_ID)

# ----------------------------------------------------------------------
# 1e. PAYMENTS — ZainCash (Iraq's mobile-wallet payment gateway)
# ----------------------------------------------------------------------
# Paddle/Stripe/Lemon Squeezy/Dodo all refuse to onboard sellers based in
# Iraq, so ZainCash is the real payment path for SpeakPort. It settles in
# Iraqi Dinar (IQD) only — the customer pays via their ZainCash mobile
# wallet (phone number + OTP), no card required. The USD price is shown
# for reference only; the real charge is always in IQD.
#
# Get these after ZainCash approves your business:
# https://zaincash.iq/business/business-wallet-registration
ZAINCASH_CLIENT_ID = os.getenv("ZAINCASH_CLIENT_ID", "").strip()
ZAINCASH_CLIENT_SECRET = os.getenv("ZAINCASH_CLIENT_SECRET", "").strip()
ZAINCASH_ENV = os.getenv("ZAINCASH_ENV", "test").strip()   # "test" or "production"
ZAINCASH_BASE_URL = (
    "https://pg-api.zaincash.iq" if ZAINCASH_ENV == "production"
    else "https://pg-api-uat.zaincash.iq"
)
ZAINCASH_CONFIGURED = bool(ZAINCASH_CLIENT_ID and ZAINCASH_CLIENT_SECRET)
# ZainCash's docs use "JAWS" as the example serviceType and describe it as
# merchant-defined — override ZAINCASH_SERVICE_TYPE in your .env if your
# business account was assigned a different value.
ZAINCASH_SERVICE_TYPE = os.getenv("ZAINCASH_SERVICE_TYPE", "JAWS").strip()

# Pro plan price. USD is display-only; PRO_PRICE_IQD is what ZainCash
# actually charges. ~1,300 IQD = $1 as of mid-2026 — adjust in your .env
# if the exchange rate moves a lot.
PRO_PRICE_USD = os.getenv("PRO_PRICE_USD", "6.99").strip()
PRO_PRICE_IQD = os.getenv("PRO_PRICE_IQD", "9100").strip()

# Max plan price — everything Pro includes, PLUS AI Roleplay (free-form AI
# conversation practice, powered by Gemini -- see GEMINI_API_KEY below).
MAX_PRICE_USD = os.getenv("MAX_PRICE_USD", "9.99").strip()
MAX_PRICE_IQD = os.getenv("MAX_PRICE_IQD", "13000").strip()

# Annual pass — a second, longer one-time option alongside the 30-day pass
# above (same ZainCash/QiCard checkout flow, just a different amount/
# duration). Defaults to 10x the monthly price ("2 months free" — a common
# annual-prepay discount), rounded to a clean number; override either env
# var directly if you want a different discount.
def _default_annual(monthly_str: str) -> str:
    try:
        return f"{round(float(monthly_str) * 10, 2):.2f}"
    except ValueError:
        return monthly_str

PRO_PRICE_USD_ANNUAL = os.getenv("PRO_PRICE_USD_ANNUAL", "").strip() or _default_annual(PRO_PRICE_USD)
PRO_PRICE_IQD_ANNUAL = os.getenv("PRO_PRICE_IQD_ANNUAL", "").strip() or _default_annual(PRO_PRICE_IQD)
MAX_PRICE_USD_ANNUAL = os.getenv("MAX_PRICE_USD_ANNUAL", "").strip() or _default_annual(MAX_PRICE_USD)
MAX_PRICE_IQD_ANNUAL = os.getenv("MAX_PRICE_IQD_ANNUAL", "").strip() or _default_annual(MAX_PRICE_IQD)

# How many days of Pro each plan grants once payment is confirmed --
# shared by ZainCash and QiCard (both one-time, non-recurring rails).
PRO_PLAN_DAYS = {"monthly": 30, "annual": 365}

# ----------------------------------------------------------------------
# 1e-2. AI ROLEPLAY — Gemini-powered free-form spoken conversation (Max only)
# ----------------------------------------------------------------------
# Google's Gemini API. Get a free key at https://aistudio.google.com/apikey --
# no credit card needed to start; the free tier is generous enough for
# testing, and Flash-tier models are the cheapest capable option once you
# outgrow it. Same demo-mode-until-configured pattern as every other
# integration in this file: until GEMINI_API_KEY is set, the AI Roleplay
# screen tells the learner it isn't turned on yet instead of erroring.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
# Google retires/restricts model names surprisingly often (gemini-2.5-flash
# stopped accepting new API keys in July 2026, for example) -- if you ever
# see a 404 "no longer available" error, check
# https://ai.google.dev/gemini-api/docs/models for whatever the current
# cheapest "Stable" Flash-Lite model is called and override it here without
# touching any code.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite").strip()
GEMINI_CONFIGURED = bool(GEMINI_API_KEY)

# ----------------------------------------------------------------------
# 1e-3. SONGS: connected-speech breakdown (Gemini)
# ----------------------------------------------------------------------
# Real licensed lyrics (Musixmatch) were considered and built, then dropped
# -- their commercial plan (needed for full songs, not just preview
# snippets) runs $49-199/month, too expensive to justify here. Songs stays
# 100% AI-original (call_gemini_song above); Gemini is still never asked to
# reproduce real copyrighted lyrics.
def call_gemini_breakdown(text: str) -> dict:
    """
    The "connected speech breakdown" technique: shows one line transforming
    from careful textbook pronunciation into fast natural speech, in the
    same 4 layers as the reference videos this feature was inspired by
    (No Rhythm -> Linking -> Reduced/Substituted -> Fluency). Works on any
    line of English -- real lyrics, AI-generated lyrics, or plain
    sentences. Returns {"literal", "linking", "reduced", "fluent"}.
    """
    system_prompt = (
        "You are a phonetics coach showing a language learner how a line of "
        "English transforms from careful textbook pronunciation into fast, "
        "natural native speech -- the same technique as: 'it was not me' -> "
        "'it ain't me'. Given one line, reply with ONLY valid JSON: "
        '{"literal": "...", "linking": "...", "reduced": "...", "fluent": "..."}. '
        "literal = the line exactly as given. linking = the same words, but "
        "insert an underscore between any words whose sounds blend/link "
        "together when spoken fast (e.g. 'it_wasn't_me'). reduced = the "
        "casual contracted/substituted form a native would actually say "
        "(e.g. 'going to'->'gonna', 'want to'->'wanna', 'wasn't'->'ain't'). "
        "fluent = a short, easy-to-read phonetic-style respelling of how it "
        "actually sounds spoken fast (e.g. 'it ain(t) me'). Keep every field "
        "short -- one line, no explanations, JSON only."
    )
    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        params={"key": GEMINI_API_KEY},
        json={
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": text}]}],
            "generationConfig": {
                "maxOutputTokens": 300, "temperature": 0.4,
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "literal": {"type": "STRING"}, "linking": {"type": "STRING"},
                        "reduced": {"type": "STRING"}, "fluent": {"type": "STRING"},
                    },
                    "required": ["literal", "linking", "reduced", "fluent"],
                },
            },
        },
        timeout=20,
    )
    if not resp.ok:
        raise HTTPException(502, f"Gemini rejected the request ({resp.status_code}): {resp.text[:500]}")
    body = resp.json()
    try:
        raw = body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, TypeError):
        reason = (body.get("candidates") or [{}])[0].get("finishReason", "unknown")
        raise HTTPException(502, f"Gemini didn't return a breakdown (reason: {reason}).")
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        data = _json.loads(raw)
        result = {k: str(data[k]).strip() for k in ("literal", "linking", "reduced", "fluent")}
        if not all(result.values()):
            raise ValueError("empty field")
    except (_json.JSONDecodeError, KeyError, ValueError, TypeError):
        raise HTTPException(502, "Gemini returned a breakdown in an unexpected format. Try again.")
    return result


def call_gemini(scenario: str, history: list, message: str) -> str:
    """
    Sends one conversation turn to Gemini and returns the AI partner's reply
    text. Stateless on purpose -- the browser holds the transcript (like the
    scripted conversations do) and resends it each turn, so there's no new
    database table / migration for this feature.
    """
    system_prompt = (
        "You are a friendly, patient conversation partner helping someone "
        "practice SPOKEN English as a second language. "
        + (f"Stay in character for this scenario: {scenario.strip()}. " if scenario.strip() else
           "This is an open, free-form conversation -- follow the learner's lead. ")
        + "Reply in English only, 1-3 short sentences, in a natural spoken "
        "style (not a wall of text). Keep the conversation going with a "
        "question or comment. If the learner makes a grammar mistake, don't "
        "interrupt the flow to correct it unless they explicitly ask you to."
    )
    contents = []
    for turn in history[-16:]:   # bound how much we resend, keeps cost + latency in check
        role = "model" if turn.get("role") == "ai" else "user"
        text = str(turn.get("text", "")).strip()
        if text:
            contents.append({"role": role, "parts": [{"text": text}]})
    contents.append({"role": "user", "parts": [{"text": message}]})

    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        params={"key": GEMINI_API_KEY},
        json={
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
            "generationConfig": {"maxOutputTokens": 200, "temperature": 0.8},
        },
        timeout=20,
    )
    if not resp.ok:
        raise HTTPException(502, f"Gemini rejected the request ({resp.status_code}): {resp.text[:500]}")
    body = resp.json()
    try:
        return body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, TypeError):
        # Most common cause: the reply was blocked by a safety filter, which
        # omits "content" entirely and puts a finishReason there instead.
        reason = (body.get("candidates") or [{}])[0].get("finishReason", "unknown")
        raise HTTPException(502, f"Gemini didn't return a reply (reason: {reason}).")


def call_gemini_translate(text: str) -> str:
    """
    One-off English -> Arabic translation via Gemini. Separate from
    call_gemini (the roleplay chat helper) -- no persona, no history, just a
    faithful translation of one piece of text. Used only as a fallback when
    _TRANSLATION_LOOKUP misses below, i.e. AI Roleplay's replies -- those
    are generated fresh every time and can never be pre-baked into that
    dictionary the way Lessons/Shadow/scripted-Conversations text is.
    """
    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        params={"key": GEMINI_API_KEY},
        json={
            "system_instruction": {"parts": [{"text":
                "Translate the given English text into natural, conversational "
                "Arabic. Reply with ONLY the Arabic translation -- no quotes, "
                "no notes, no English."
            }]},
            "contents": [{"role": "user", "parts": [{"text": text}]}],
            "generationConfig": {"maxOutputTokens": 200, "temperature": 0.2},
        },
        timeout=15,
    )
    if not resp.ok:
        raise HTTPException(502, f"Gemini translate failed ({resp.status_code}): {resp.text[:300]}")
    body = resp.json()
    try:
        return body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, TypeError):
        return ""


def call_gemini_song(theme: str, level: str) -> dict:
    """
    Writes a short, wholly ORIGINAL practice "song" for the Songs feature
    (Max only). Deliberately never touches real/copyrighted lyrics -- there's
    no music-licensing deal here, so every song is a brand-new creation,
    generated fresh and never stored. Returns {"title": str, "lines": [str]}.
    """
    theme_clause = f'about "{theme.strip()}"' if theme.strip() else "about an everyday topic a language learner would enjoy"
    system_prompt = (
        "You write short, wholly ORIGINAL practice songs for English language "
        "learners. Never reuse, quote, or closely imitate any real, existing "
        "song's lyrics, title, or artist -- everything you write must be your "
        "own brand-new creation. "
        f"Write a simple, singable original song {theme_clause}, using "
        f"vocabulary and sentence length appropriate for a {level} English "
        "learner. Include a simple repeated chorus line so it's easy to "
        "practice. Reply with ONLY valid JSON matching this exact shape: "
        '{"title": "...", "lines": ["...", "..."]}. '
        "8 to 14 short lines total, each short enough to say in a single "
        "breath (roughly 4-9 words). No markdown, no commentary -- JSON only."
    )
    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        params={"key": GEMINI_API_KEY},
        json={
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": "Write the song now."}]}],
            "generationConfig": {
                "maxOutputTokens": 500, "temperature": 0.9,
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "title": {"type": "STRING"},
                        "lines": {"type": "ARRAY", "items": {"type": "STRING"}},
                    },
                    "required": ["title", "lines"],
                },
            },
        },
        timeout=25,
    )
    if not resp.ok:
        raise HTTPException(502, f"Gemini rejected the request ({resp.status_code}): {resp.text[:500]}")
    body = resp.json()
    try:
        raw = body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, TypeError):
        reason = (body.get("candidates") or [{}])[0].get("finishReason", "unknown")
        raise HTTPException(502, f"Gemini didn't return a song (reason: {reason}).")

    # responseSchema makes this reliable, but defensively strip a markdown
    # fence in case one ever slips through anyway.
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        data = _json.loads(raw)
        title = str(data["title"]).strip()
        lines = [str(ln).strip() for ln in data["lines"] if str(ln).strip()]
        if not title or not lines:
            raise ValueError("empty title or lines")
    except (_json.JSONDecodeError, KeyError, ValueError, TypeError):
        raise HTTPException(502, "Gemini returned a song in an unexpected format. Try again.")
    return {"title": title, "lines": lines[:16]}


# ----------------------------------------------------------------------
# 1f. PAYMENTS — QiCard / "Pay with SuperQi" (a second, separate Iraqi
# payment rail alongside ZainCash — reaches customers who hold a Qi Card
# issued through Rafidain Bank or Rasheed Bank, a very large slice of
# Iraq's banked population, e.g. government employees and pensioners)
# ----------------------------------------------------------------------
# Unlike ZainCash, QiCard doesn't publish self-serve sandbox credentials —
# you request a Terminal ID + Basic Auth username/password from Qi Card's
# merchant team (https://qi.iq/en/merchants/online-payment-gateway or
# qicard@qi.iq) before this can be tested end-to-end. Their hosted checkout
# page (the "formUrl" returned below) offers both card payment and "Pay
# with SuperQi" (their QR/wallet method) — we don't choose between them,
# QiCard's own page does.
QICARD_TERMINAL_ID = os.getenv("QICARD_TERMINAL_ID", "").strip()
QICARD_USERNAME = os.getenv("QICARD_USERNAME", "").strip()
QICARD_PASSWORD = os.getenv("QICARD_PASSWORD", "").strip()
QICARD_ENV = os.getenv("QICARD_ENV", "test").strip()   # "test" or "production"
QICARD_BASE_URL = (
    # NOTE: the production host isn't published in QiCard's public docs —
    # confirm the real value with your Qi Card account manager once you
    # have live credentials, and set QICARD_BASE_URL_OVERRIDE if it differs.
    os.getenv("QICARD_BASE_URL_OVERRIDE", "").strip()
    or ("https://api.qi.iq" if QICARD_ENV == "production"
        else "https://uat-sandbox-3ds-api.qi.iq")
)
QICARD_CONFIGURED = bool(QICARD_TERMINAL_ID and QICARD_USERNAME and QICARD_PASSWORD)

# ----------------------------------------------------------------------
# 1b. CONTENT CONFIG  (everything is offline — no API, no keys, no limits)
# ----------------------------------------------------------------------
# SpeakPort runs entirely on built-in content (see content.py). There are no
# API keys, no rate limits, and no per-user cost. Practice sentences and
# conversations are all pre-written and translated, so the app works the
# same for one user or a million.
from content import (SENTENCE_BANK, CONVERSATIONS, CONVERSATION_BY_ID,
                     SPRINT_CONVS, SPRINT_CONVS_BIZ, SHADOW_CATEGORIES,
                     JOURNAL_PROMPTS, IRREGULAR_VERB_MISTAKES)

# The learner's first language, for showing translations. Arabic is default.
# Translations are baked into content.py per sentence/line.
SUPPORTED_L1 = {"ar": "Arabic"}



# ----------------------------------------------------------------------
# 2. DATABASE
# ----------------------------------------------------------------------
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    # Optional display name, set from Account Settings (or auto-filled from
    # Google's "name" claim on first Google sign-in). Falls back to email
    # everywhere in the UI when unset.
    name: str | None = None
    # True for every normal registered/reset account. False ONLY for a
    # Google-only account that has never set a real password — its
    # hashed_password is an unusable random value, so this flag is the one
    # source of truth for "Change password" vs. "Set a password" in the UI,
    # and for whether email+password login should even be attempted.
    has_password: bool = True
    is_premium: bool = False
    is_admin: bool = False
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    # Real-subscription tracking. These stay empty/"none" for admin-comped
    # Pro users and in demo mode — only the payment webhook ever writes to
    # paddle_subscription_id and subscription_status.
    paddle_customer_id: str | None = None
    paddle_subscription_id: str | None = None
    subscription_status: str = "none"   # "none" | "active" | "past_due" | "canceled"
    # ZainCash tracking. ZainCash payments aren't recurring subscriptions —
    # each successful payment buys 30 days of Pro, tracked via pro_expires_at.
    zaincash_transaction_id: str | None = None
    pro_expires_at: dt.datetime | None = None
    # QiCard (Pay with SuperQi) tracking — same one-time-purchase model as
    # ZainCash, sharing the same pro_expires_at field.
    qicard_payment_id: str | None = None
    # Which calendar day (ISO date string) this user last saw the "new
    # phrases today" dashboard banner. Compared against today's date so the
    # banner shows once per day instead of nagging on every page load.
    last_seen_phrase_day: str | None = None
    # Optional learning goal ("travel" | "work" | "exam"), set from Account
    # Settings. Purely a content-surfacing hint (see GOAL_TAGS) -- nothing
    # is ever hidden based on it, matching this app's "no artificial limits"
    # design. None means no preference / show everything unranked.
    goal: str | None = None
    # Which one-time pass ("monthly" | "annual") the customer picked at
    # ZainCash/QiCard checkout -- set right before redirecting them to pay,
    # read back at grant time (whether that's the redirect callback, the
    # webhook, or the /sync fallback) so all three grant the right number
    # of days. Irrelevant for Paddle, which tracks its own billing interval.
    checkout_plan: str = "monthly"
    # Which tier ("pro" | "max") this user's Pro access is currently at --
    # Max adds AI Roleplay on top of everything Pro includes. Deliberately
    # separate from is_premium (which stays a plain "has paid access" bool
    # used by ~20 existing gates across the app) so introducing tiers can't
    # touch any of those. Only meaningful while is_premium is True.
    plan_tier: str = "pro"
    # Which tier the customer picked at ZainCash/QiCard checkout -- same
    # role as checkout_plan above, just for tier instead of billing period.
    checkout_tier: str = "pro"


class Attempt(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    lesson_id: str
    phrase_index: int
    score: int  # 0-100
    transcript: str = ""
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class Enrollment(SQLModel, table=True):
    """One row when a user starts the sprint. started_at drives day unlocking."""
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    sprint_id: str
    started_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class DayCompletion(SQLModel, table=True):
    """One row per sprint day whose DRILL stage (the phrase repeats) is passed."""
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    sprint_id: str
    day_number: int
    avg_score: int
    completed_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class DayConvDone(SQLModel, table=True):
    """
    One row per sprint day whose CONVERSATION stage is finished.
    A day only counts as fully cleared when BOTH this and DayCompletion
    exist for it — drill first, then a real CLT conversation.
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    sprint_id: str
    day_number: int
    completed_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class PasswordReset(SQLModel, table=True):
    """
    One row per "forgot password" request. The token is a long random
    string (not guessable), expires in an hour, and can only be used once —
    standard password-reset hygiene.
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    token: str = Field(index=True, unique=True)
    expires_at: dt.datetime
    used: bool = False
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class ReviewItem(SQLModel, table=True):
    """
    One row per (user, practiced item) — a simple Leitner-box spaced-
    repetition schedule for Lessons + Shadow Mode phrases. Box 1 = due
    again very soon; box 5 = "mastered," reviewed rarely. A strong score
    (>=85) advances a box (longer gap); a weak one resets to box 1 (back
    soon), so struggling phrases resurface sooner than ones already nailed.

    item_id is "lesson:{lesson_id}:{phrase_index}" or
    "shadow:{category_id}:{phrase_index}" — both stable, so a Timed Drill
    sentence (a big shuffled bank, no stable per-sentence identity) or a
    scripted conversation (branching dialogue, not a flashcard) never gets
    tracked here — only the fixed practice content that's actually possible
    to "finish" and needs a reason to resurface.
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    item_id: str = Field(index=True)
    box: int = 1
    next_review_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    last_score: int = 0
    updated_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


class LeagueMembership(SQLModel, table=True):
    """
    Which Speaking League tier a user is currently in, and which week that
    reflects. Cohorts themselves are deliberately NOT stored as their own
    table -- like the daily phrase rotation, a cohort is recomputed
    deterministically each week from (tier, week, sorted user_ids), so
    there's nothing to keep in sync and no separate cleanup needed when
    users come and go.
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, unique=True)
    tier: int = 0   # index into LEAGUE_TIERS -- 0 = Bronze
    updated_week: str = ""   # ISO date (Monday) this tier assignment reflects


class LeagueRollupState(SQLModel, table=True):
    """
    Singleton row (there's only ever one) tracking the last week whose
    promotions/demotions were fully processed. Whichever request happens
    to be the first one made after a new week starts triggers the
    rollover for EVERYONE at once, so every user's cohort for the new week
    is computed from a consistent, already-settled set of tiers -- never a
    mix of some users rolled over and others not yet.
    """
    id: int | None = Field(default=None, primary_key=True)
    last_rolled_week: str = ""


class StreakShieldUse(SQLModel, table=True):
    """
    One row per calendar day a Pro user's daily streak was auto-protected
    by their always-on Streak Shield perk. Recorded permanently (rather
    than just silently fudging the streak number) so it only ever covers
    a given missed day once, and so it's auditable.
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    shielded_date: str = Field(index=True)   # ISO date string of the protected day


class JournalEntry(SQLModel, table=True):
    """
    One row per (user, calendar day) they completed the Voice Journal --
    a free-form 60-second spoken prompt (Pro). At most one per user per
    day; a second attempt the same day just returns the existing row
    instead of creating a duplicate (no double XP, no gaming the streak).
    """
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    entry_date: str = Field(index=True)      # ISO date string, the day this entry counts for
    prompt_en: str = ""
    transcript: str = ""
    duration_sec: int = 0
    word_count: int = 0
    created_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


# ----------------------------------------------------------------------
# 1c. DATABASE — SQLite locally (zero setup), Postgres in production
# ----------------------------------------------------------------------
# Locally, with no DATABASE_URL set, this uses a SQLite file (app.db) —
# nothing to install, works immediately.
#
# In production, set DATABASE_URL to a Postgres connection string and data
# survives restarts/redeploys. On Render this is done automatically if you
# attach a Postgres database in the dashboard (or via render.yaml).
#
# Render/Heroku-style platforms hand out URLs starting with "postgres://",
# but SQLAlchemy 2.x requires "postgresql://" — this line fixes that
# mismatch so you don't hit a cryptic error on first deploy.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# The same signal doubles as a general "are we running for real" flag —
# used to lock down local-only conveniences (like the password-reset demo
# link below) so they can never accidentally run in production.
IS_PRODUCTION = bool(DATABASE_URL)

if DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,   # drops stale connections instead of erroring on them
    )
else:
    engine = create_engine(
        f"sqlite:///{BASE_DIR / 'app.db'}",
        connect_args={"check_same_thread": False},
    )

# Create the database tables on startup (safe to run every time, on either DB).
# This alone only creates tables that don't exist yet — it does NOT add new
# columns to a table that already exists. That gap is exactly what caused a
# real bug: an older app.db missing newly-added columns made every login
# crash with "no such column: user.paddle_customer_id". The function below
# closes that gap for good.
SQLModel.metadata.create_all(engine)


def run_auto_migrations(engine):
    """
    Self-healing schema migration, run on every startup.

    Compares what SQLModel says each table SHOULD have against what the
    actual database table HAS, and adds any missing columns with ALTER
    TABLE. This is intentionally narrow in scope — it only ever ADDS
    columns, never renames, drops, or changes types — because that additive
    case covers every schema change this app has actually made so far, and
    it's the one kind of change that's always safe to automate: existing
    data is never touched, only new columns are introduced.

    Renaming a column or changing its type still needs a human to write a
    real migration — this function will print a clear warning if it can't
    safely handle something, rather than guessing.
    """
    inspector = sa_inspect(engine)
    existing_tables = set(inspector.get_table_names())
    migrated_anything = False

    for table_name, table in SQLModel.metadata.tables.items():
        if table_name not in existing_tables:
            continue   # brand-new table — create_all() already handled this
        existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
        missing = [c for c in table.columns if c.name not in existing_cols]
        if not missing:
            continue

        added = []
        for col in missing:
            try:
                col_type = col.type.compile(dialect=engine.dialect)
                clause = f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {col_type}'

                default_sql = None
                if col.default is not None and getattr(col.default, "is_scalar", False):
                    val = col.default.arg
                    if isinstance(val, bool):
                        default_sql = "TRUE" if val else "FALSE"
                    elif isinstance(val, (int, float)):
                        default_sql = str(val)
                    elif isinstance(val, str):
                        default_sql = "'" + val.replace("'", "''") + "'"
                # A scalar default lets us backfill existing rows AND keep
                # the column non-nullable, matching what the model expects.
                if default_sql is not None and not col.nullable:
                    clause += f" NOT NULL DEFAULT {default_sql}"
                elif default_sql is not None:
                    clause += f" DEFAULT {default_sql}"
                # else: no static default available (e.g. a default_factory
                # like datetime.utcnow) — add it nullable so startup never
                # crashes; existing rows get NULL for this column, which is
                # honest given we have no single right value to backfill.

                with engine.begin() as conn:
                    conn.execute(sa_text(clause))
                added.append(col.name)
            except Exception as e:
                print(f"  ⚠️  Could not auto-add column {table_name}.{col.name}: {e}")
                print(f"      You'll need to add this column manually.")

        if added:
            migrated_anything = True
            print(f"  🔧 Migrated '{table_name}': added column(s) {', '.join(added)}")

    if not migrated_anything:
        pass   # nothing to do — schema already matches, the common case


run_auto_migrations(engine)


def get_session():
    with Session(engine) as session:
        yield session


# ----------------------------------------------------------------------
# 3. LESSONS  (edit this list to add your own content)
# ----------------------------------------------------------------------
LESSONS = [
    {
        "id": "greetings",
        "title": "Greetings & Introductions",
        "level": "Beginner",
        "is_premium": False,
        "phrases": [
            'Hello, nice to meet you.',
            "My name is Sara. What's your name?",
            'Where are you from?',
            "I'm learning English to travel.",
            'It was great talking to you.',
            'Hi there, how are you doing today?',
            "Good morning! It's nice to meet you.",
            "Good afternoon, I don't think we've met yet.",
            "Hi, I'm glad we finally get to talk.",
            "Hello, I've heard a lot about you.",
            'Nice to finally put a face to the name.',
            "Hi, I don't believe we've been introduced.",
            "Good evening, it's a pleasure to meet you.",
            'Hello, welcome! Make yourself at home.',
            "Sorry, I didn't catch your name.",
            'Can you tell me your name again?',
            'What should I call you?',
            'Is it okay if I call you by your first name?',
            'How do you spell your last name?',
            'My friends call me Sam, by the way.',
            'I go by my middle name, actually.',
            "What's your full name, if you don't mind me asking?",
            'Nice name — where does it come from?',
            'Which city do you live in?',
            'Have you always lived here?',
            "I'm originally from Basra, but I moved here recently.",
            'What part of the country are you from?',
            'Do you go back home often?',
            'How long have you lived in this city?',
            'Is this your hometown?',
            "I've never been to your country — what's it like?",
            'What brought you to this city?',
            'I work in marketing, and you?',
            "I'm a student at the local university.",
            'I moved here a few months ago for work.',
            "I've been studying English for about a year.",
            "I'm here on a short business trip.",
            "I'm still new to this city, actually.",
            'I spend most of my free time reading.',
            'I have two younger siblings back home.',
            'I recently changed careers.',
            'How are you doing today?',
            "How's everything going?",
            'How have you been lately?',
            'Is everything okay with you?',
            'You seem happy today — good news?',
            'How was your weekend?',
            "How's your family doing?",
            "How's work been treating you?",
            'Everything going well on your end?',
            "It's been a while — how have things been?",
            'This is my colleague, Ahmed.',
            'Have you two met before?',
            'Let me introduce you to my friend.',
            "I'd like you to meet my manager.",
            'This is Layla, she just joined our team.',
            'Allow me to introduce my wife.',
            'Meet my neighbor, he just moved in.',
            "I don't think you've met my brother yet.",
            "This is someone I'd love for you to know.",
            'Let me introduce the two of you properly.',
            "Lovely weather we're having today, isn't it?",
            "It's quite hot outside today.",
            'I heard it might rain later.',
            'This has been a busy week for me.',
            "It's finally starting to feel like spring.",
            "I can't believe how cold it got last night.",
            'Is it always this humid here in summer?',
            'What a beautiful morning!',
            'I hope the weather stays nice for the weekend.',
            'It looks like a storm is coming.',
            'I should get going, but it was nice meeting you.',
            "Let's catch up again soon.",
            'Take care, and see you around.',
            "I'll see you next time, then.",
            'Have a safe trip home.',
            'It was a pleasure meeting you today.',
            'I hope we can talk again soon.',
            'Goodbye for now, take care of yourself.',
            'Thanks for the chat — see you later.',
            "Hi, I'm the new intern in the marketing team.",
            'I just started here last week.',
            'Which department do you work in?',
            "I've heard great things about your team.",
            'Are you also new here?',
            'I look forward to working with you.',
            'Who should I talk to about the project timeline?',
            "I'm still learning where everything is around the office.",
            'Let me know if you need any help settling in.',
            'I sit just down the hall, feel free to stop by.',
            "It's been a long time since we last spoke.",
            "Wow, I didn't expect to run into you here!",
            'How funny running into you like this.',
            "It's so good to see a familiar face.",
            'We should really catch up properly sometime.',
            'I still remember the last time we met.',
            "You haven't changed a bit!",
            "Small world, isn't it?",
            "Let's exchange numbers so we don't lose touch again.",
            "I'm really glad our paths crossed again.",
        ],
    },
    {
        "id": "cafe",
        "title": "Ordering at a Café",
        "level": "Beginner",
        "is_premium": False,
        "phrases": [
            'Could I have a coffee, please?',
            'Do you have any tea without sugar?',
            'How much is this sandwich?',
            'Can I pay by card?',
            'Thank you, have a nice day.',
            "I'll have a cappuccino, please.",
            'Can I get a large iced latte?',
            "I'd like a hot chocolate, please.",
            'One black coffee, please, no sugar.',
            'Could I get an espresso shot?',
            "I'll take a medium tea, please.",
            'Can I have a decaf coffee?',
            "I'd like an iced tea, please.",
            'Could you make that a double espresso?',
            'What do you have on the menu today?',
            "What's your most popular drink?",
            'Do you have any specials today?',
            'What kind of teas do you offer?',
            'Could I see the menu, please?',
            "What's in this drink exactly?",
            'Do you serve any seasonal drinks?',
            'Is this drink served hot or cold?',
            "What would you recommend for someone who doesn't like it too sweet?",
            'Do you have a menu in English?',
            'Do you accept cash?',
            'Is service included in the price?',
            'Could I get a receipt, please?',
            'How much do I owe you?',
            'Is there a discount for students?',
            'Can I split the bill with my friend?',
            'Do you take contactless payment?',
            'Is there an extra charge for oat milk?',
            'Could you add a little extra sugar?',
            'Can I get that with oat milk instead?',
            'No sugar for me, please.',
            'Could you make it extra hot?',
            'Can I get an extra shot of espresso?',
            "I'd like less ice in my drink, please.",
            'Could you leave out the whipped cream?',
            'Can you make it a bit sweeter?',
            "I'll take that with skimmed milk, please.",
            'Could I get it to go, extra strong?',
            'Could I also get a croissant?',
            'Do you have any fresh pastries today?',
            "I'll take a slice of that cake, please.",
            'Is this muffin freshly baked?',
            'Could I get a sandwich to go with my coffee?',
            'What pastries pair well with black coffee?',
            'Can I get that warmed up, please?',
            'Do you have any gluten-free options?',
            "I'll have a cookie with my order, please.",
            'Could you recommend something sweet?',
            'Is this milk lactose-free?',
            'Do you have a dairy-free option?',
            'Is there any sugar-free syrup available?',
            'Could you make this without caffeine?',
            'Do you have any vegan pastries?',
            'Is this drink suitable for someone with a nut allergy?',
            'Could I get that without any added sweetener?',
            'Do you offer plant-based milk alternatives?',
            'Is this completely sugar-free?',
            'Is this for here or to go?',
            "I'll have it here, please.",
            'Could I get this to take away?',
            'Is there a table available inside?',
            'Can I sit outside on the terrace?',
            'Do you have Wi-Fi here?',
            'Could you bring it to my table?',
            'Is it okay if I sit here?',
            "I'd like to take this with me, please.",
            'Could I get a cup holder for these?',
            "I think this isn't what I ordered.",
            'Could I get some extra napkins, please?',
            'Sorry, could you remake this one?',
            'This coffee seems a bit cold.',
            'Could I get a straw, please?',
            'I ordered this without sugar, actually.',
            'Could you check if this is the right size?',
            'Sorry, I think you gave me the wrong drink.',
            'Could I get some more hot water, please?',
            'This seems too strong for me — could you add more milk?',
            'That was delicious, thank you.',
            'Everything was great, thanks so much.',
            'Thanks for the quick service.',
            'I really enjoyed that, thank you.',
            'Have a good one, thanks again.',
            'That hit the spot, thank you.',
            "Thanks, I'll definitely come back.",
            'I appreciate it, have a great day.',
            'Thank you, that was exactly what I needed.',
            'What would you recommend for a first-time visitor?',
            "What's your personal favorite here?",
            'Could you recommend something not too sweet?',
            'What do most people order in the morning?',
            "Is there something you'd suggest for someone who loves chocolate?",
            'What pairs well with a croissant?',
            'Could you suggest a good afternoon pick-me-up?',
            "What's a popular drink for someone who doesn't like coffee?",
            'Do you have a bestseller I should try?',
            'What would you recommend on a hot day like today?',
        ],
    },
    {
        "id": "interview",
        "title": "Job Interview Basics",
        "level": "Intermediate",
        "is_premium": True,
        "phrases": [
            'Thank you for inviting me to this interview.',
            'I have three years of experience in this field.',
            'I work well both independently and in a team.',
            'My greatest strength is solving problems quickly.',
            'When can I expect to hear back from you?',
            'Thank you for taking the time to meet with me today.',
            'I really appreciate the opportunity to speak with you.',
            "It's a pleasure to finally meet you in person.",
            "Thank you for having me — I've been looking forward to this.",
            "I'm glad we could arrange this interview.",
            'Thank you for considering my application.',
            "It's an honor to be interviewing for this role.",
            'I appreciate you fitting me into your schedule.',
            'Thank you for the warm welcome.',
            "I've worked in customer service for over five years.",
            'My background is mainly in project management.',
            "I've held a similar position at my previous company.",
            'I gained a lot of hands-on experience during my last role.',
            "I've led a small team for the past two years.",
            'My experience includes both remote and in-office work.',
            "I've worked across several different industries.",
            'I completed an internship in this exact field last year.',
            "I've been responsible for managing client accounts since 2022.",
            "I'm known for staying calm under pressure.",
            'I pay close attention to detail in everything I do.',
            "I'm a quick learner and adapt easily to new systems.",
            "I'm very organized and rarely miss a deadline.",
            'I communicate clearly, even in stressful situations.',
            "I'm good at motivating the people around me.",
            'I take initiative without needing to be asked.',
            "I'm comfortable juggling multiple projects at once.",
            "I sometimes take on too much at once, but I'm learning to delegate.",
            'I used to struggle with public speaking, so I joined a course to improve.',
            'I can be overly critical of my own work.',
            "I'm working on saying no when my plate is already full.",
            "I used to avoid conflict, but I've learned to address issues directly.",
            "I'm still improving my skills with data analysis tools.",
            'I sometimes spend too long perfecting small details.',
            "I'm learning to ask for help sooner rather than later.",
            'I used to find it hard to switch off after work.',
            "I'm working on being more concise in my reports.",
            "I've always admired this company's work in this industry.",
            "This role matches exactly what I'm looking for in my career.",
            "I'm excited about the direction this company is heading.",
            "Your company's values really align with mine.",
            "I've followed this company's growth for a while now.",
            'This position feels like the natural next step for me.',
            "I'm drawn to the team culture I've heard about here.",
            'I want to grow my career somewhere that values innovation.',
            "This role would let me use skills I don't get to use enough currently.",
            "I've heard great things about the team I'd be joining.",
            'I work well both independently and as part of a team.',
            'I enjoy collaborating with people from different backgrounds.',
            'I believe the best results come from open communication within a team.',
            "I've mentored a few junior colleagues in my current role.",
            "I'm comfortable giving and receiving constructive feedback.",
            "I try to make sure everyone's voice is heard in a meeting.",
            "I've worked closely with cross-functional teams before.",
            'I enjoy brainstorming solutions together rather than alone.',
            "I try to support my teammates whenever they're overloaded.",
            'I value transparency when working toward a shared goal.',
            'When I face a difficult problem, I break it down into smaller steps.',
            'I once resolved a major client complaint under a tight deadline.',
            'I stay focused on solutions rather than dwelling on the problem.',
            'I always look for the root cause before reacting.',
            "I've learned to stay flexible when plans suddenly change.",
            'I try to view setbacks as opportunities to improve.',
            'I once had to manage a project after losing a key team member.',
            'I ask clarifying questions early to avoid bigger issues later.',
            'I stay calm and prioritize when several things go wrong at once.',
            'I usually involve my team when solving a complex problem.',
            'Could you tell me more about the salary range for this role?',
            'What does the benefits package typically include?',
            'Is remote work an option for this position?',
            'What would the working hours look like?',
            'When would you expect the successful candidate to start?',
            'Are there opportunities for growth within the company?',
            'How is performance usually reviewed here?',
            'Is relocation assistance offered for this role?',
            'What does a typical career path look like from this position?',
            'Could you walk me through the next steps in the hiring process?',
            'What does success look like in this role after the first year?',
            'What do you enjoy most about working here?',
            "How would you describe the team's day-to-day dynamic?",
            'What are the biggest challenges facing the team right now?',
            'How does the company support professional development?',
            "What's the management style like on this team?",
            'Is there anything about my background that gives you concern?',
            'How has this role evolved over the past few years?',
            'What made you decide to join this company?',
            'What are the next steps after this interview?',
            'Thank you again for this opportunity.',
            "I'm very enthusiastic about the possibility of joining your team.",
            'Please let me know if you need any further information from me.',
            'I look forward to hearing from you soon.',
            "Thank you for your time today — it's been a pleasure.",
            "I'm confident I could contribute a lot to this role.",
            "Is there anything else you'd like to know about me?",
            'Thanks again, I really enjoyed our conversation.',
            'I appreciate your consideration and look forward to next steps.',
        ],
    },
    {
        "id": "travel",
        "title": "Travel & Airport",
        "level": "Intermediate",
        "is_premium": True,
        "phrases": [
            'Where is the check-in counter for this flight?',
            'I would like a window seat, please.',
            'How long is the layover in Istanbul?',
            'Excuse me, is this the gate for the London flight?',
            'Could you help me find my luggage?',
            'Could I check in for my flight, please?',
            "Here's my passport and booking reference.",
            'Is online check-in available for this flight?',
            'Could I get a boarding pass, please?',
            'How many bags am I allowed to check in?',
            'Is there a fee for checking an extra bag?',
            'Could you confirm my flight number, please?',
            'What time does check-in close for this flight?',
            'Could I check in a bit early?',
            'Where is airport security located?',
            'Do I need to remove my laptop from my bag?',
            'Which gate does this flight board from?',
            'What time does boarding start?',
            'Is priority boarding available for this flight?',
            'Could you tell me where gate B12 is?',
            'Is this the line for security?',
            'Do I need to take off my shoes here?',
            'How long is the wait through security today?',
            'Could I get an aisle seat instead?',
            'Is it possible to sit next to my family?',
            'Are there any exit row seats available?',
            'Could I upgrade my seat for this flight?',
            'Is there extra legroom available on this flight?',
            'Could you check if a middle seat is free?',
            "I'd prefer not to sit near the back, if possible.",
            'Can we be seated together as a family?',
            'Is there a fee to choose my seat in advance?',
            'Do I need to collect my bags during the layover?',
            'Is there enough time to make my connecting flight?',
            'Which terminal does my connecting flight depart from?',
            'Do I need to go through security again for my next flight?',
            'Is there a lounge I can wait in during the layover?',
            'What happens if I miss my connecting flight?',
            'Is my luggage checked through to my final destination?',
            'How do I find my connecting gate?',
            'Is there a shuttle between terminals here?',
            "My suitcase hasn't arrived on the belt yet.",
            'Where is the baggage claim for this flight?',
            'I think my bag has been damaged.',
            'Is there a lost and found for luggage here?',
            'How much does an extra checked bag cost?',
            'Could I get a luggage cart, please?',
            'My bag seems to be missing — who should I speak to?',
            'Is this the right carousel for flight 245?',
            'Could you help me wrap my suitcase?',
            'Has this flight been delayed?',
            "What's causing the delay?",
            'Could you tell me the new departure time?',
            'Is there a chance this flight will be cancelled?',
            'Can I be rebooked onto an earlier flight?',
            'Will I be compensated for this delay?',
            'Is there a hotel voucher available for this overnight delay?',
            'Could you update me if the gate changes?',
            "How will I be notified if there's a further delay?",
            'Is there another flight I could take today instead?',
            'Do I need to fill out a customs form?',
            'Where is the immigration counter?',
            'How long am I allowed to stay with this visa?',
            "Do I need to declare anything I'm carrying?",
            'Is this the correct line for visitors?',
            'Could you stamp my passport, please?',
            "What's the purpose of your visit, they asked me?",
            'Do I need a return ticket to enter the country?',
            'Where do I collect my baggage after immigration?',
            'Is there anything I need to pay at customs?',
            'Excuse me, where is the nearest restroom?',
            'Could you point me toward the food court?',
            'Where can I find a currency exchange counter?',
            'Is there a pharmacy inside the airport?',
            'Which way is the exit to the taxi stand?',
            'Where can I charge my phone around here?',
            'Is there an ATM nearby?',
            'Could you show me the way to gate 22?',
            'Where is the information desk?',
            'Is there a quiet area where I can rest?',
            'Could you recommend a hotel close to the airport?',
            'Is there a shuttle to the hotels nearby?',
            'How do I get a taxi from here?',
            'Is public transport available to the city center?',
            'Could you help me book a rental car?',
            "What's the best way to get downtown from here?",
            'Is there a train that goes directly to the city?',
            'How long does it take to reach the hotel from here?',
            'Could you write the hotel address down for the driver?',
            'Is it safe to take a taxi at this hour?',
            'Is this your first time visiting this country?',
            'Are you traveling for business or pleasure?',
            'How long are you planning to stay?',
            'Is this a direct flight or do you have a connection?',
            'Have you traveled this route before?',
            "What's the best thing about traveling for you?",
            'Do you travel often for work?',
            'What made you choose this destination?',
            'Are you excited about this trip?',
            'Safe travels — I hope you enjoy your trip.',
        ],
    },
    {
        "id": "business",
        "title": "Business Meetings",
        "level": "Advanced",
        "is_premium": True,
        "phrases": [
            "Let's begin by reviewing last quarter's results.",
            "I'd like to add one point to the agenda.",
            'Could you clarify what you mean by that?',
            'I think we should postpone this decision.',
            "Let's schedule a follow-up meeting for next week.",
            'Thank you all for joining on such short notice.',
            "Let's get started, since everyone's here now.",
            "I'd like to welcome our new team members before we begin.",
            "Let's kick things off with a quick recap of last week.",
            "Shall we get started with today's agenda?",
            'Thanks everyone for making time for this meeting.',
            "Let's dive straight into today's main topic.",
            'Before we start, does anyone have anything urgent to raise?',
            "Let's open the floor with a brief round of updates.",
            'Could we move this item further down the agenda?',
            "Let's stick closely to the agenda to save time.",
            'We have three items to cover today.',
            "Let's table that discussion for our next meeting.",
            'Can we revisit the agenda for a moment?',
            'I think we should prioritize the budget item first.',
            "Let's skip ahead to the next agenda item.",
            "We're running short on time, so let's focus on the essentials.",
            "Is there anything missing from today's agenda?",
            'As you can see from this chart, sales have grown steadily.',
            'Let me walk you through the numbers from last month.',
            'This slide summarizes our key findings so far.',
            'The data clearly shows a shift in customer behavior.',
            "Let's take a closer look at this trend.",
            'According to our latest report, revenue is up twelve percent.',
            "I'll share my screen to show you the full breakdown.",
            'These figures reflect our performance over the last quarter.',
            'Let me highlight the most important takeaway from this slide.',
            "This graph illustrates where we're losing the most customers.",
            'Sorry, could you repeat that last point?',
            'When you say "next quarter," do you mean this fiscal year?',
            'Could you explain how that number was calculated?',
            "I'm not sure I followed — could you elaborate?",
            'What exactly do you mean by "scaling faster"?',
            'Could you give an example to illustrate that point?',
            'Just to confirm, are we changing the deadline or the scope?',
            'Could you break that down a bit further for me?',
            'Sorry, I want to make sure I understood that correctly.',
            'I see it a little differently, if I may.',
            "I'm not entirely convinced this is the right approach.",
            "That's a fair point, but I'd like to offer another perspective.",
            'I understand the reasoning, but I have some reservations.',
            'Could we consider an alternative before finalizing this?',
            "I'd push back slightly on that assumption.",
            'I respect that view, though I lean toward a different plan.',
            "Let's make sure we've considered the risks before agreeing.",
            "I'm hesitant to commit to that timeline just yet.",
            "I'd like to propose we move the launch date forward.",
            'My suggestion would be to test this with a smaller group first.',
            "Let's go with option two, given the budget constraints.",
            'I recommend we revisit this decision next month.',
            'Shall we vote on this before moving on?',
            'I think the safest option is to delay by one week.',
            "Let's agree on a plan and commit to it today.",
            "I'd like to put forward a different solution.",
            'Given the data, I think we should proceed with the second option.',
            "Let's finalize this decision before the end of the meeting.",
            "I'll take ownership of the client report.",
            'Could you follow up with the design team by Friday?',
            "Let's assign clear owners to each action item.",
            "I'll send everyone a summary after this call.",
            'Who can take the lead on this task?',
            "Let's make sure each action item has a deadline attached.",
            "I'll coordinate with finance on the budget approval.",
            'Could someone volunteer to draft the proposal?',
            "Let's confirm responsibilities before we wrap up.",
            "What's a realistic deadline for this project?",
            'Can we commit to delivering this by the end of the month?',
            "I'm concerned this timeline might be too tight.",
            "Let's build in some buffer time before the deadline.",
            'When do you expect the first draft to be ready?',
            'Is there any flexibility in the delivery date?',
            'We need to move faster if we want to hit this deadline.',
            "Let's set a checkpoint halfway through the timeline.",
            'I think we can realistically finish this in three weeks.',
            'Could we push the deadline back by a few days?',
            "Let's wrap up with a quick summary of today's decisions.",
            'Does anyone have any final questions before we close?',
            "I think we've covered everything on today's agenda.",
            'Thanks everyone, this was a productive discussion.',
            "Let's end there and pick this up again next week.",
            "Before we finish, let's confirm our next steps.",
            "I'll send the meeting notes out by this afternoon.",
            'Thank you all for your input today.',
            "Let's close the meeting here unless anyone objects.",
            "Great discussion, everyone — let's reconvene next week.",
            "I'll follow up with an email summarizing our decisions.",
            'Please let me know if I missed anything in the notes.',
            "I'll circulate the updated timeline by tomorrow.",
            'Feel free to reach out if anything is unclear.',
            "I'll loop in the rest of the team on this thread.",
            "Let's keep each other updated as things progress.",
            "I'll share the recording for anyone who couldn't join.",
            'Please review the document before our next call.',
            "I'll follow up individually with anyone who has questions.",
            'Looking forward to our next update on this.',
        ],
    },
]

LESSON_BY_ID = {lesson["id"]: lesson for lesson in LESSONS}
SHADOW_BY_ID = {cat["id"]: cat for cat in SHADOW_CATEGORIES}


# ----------------------------------------------------------------------
# 3b. THE SPRINT — the paid, time-boxed intensive course
# ----------------------------------------------------------------------
# This is the site's competitive advantage. Other sites sell endless lessons
# with no urgency. This is a 14-day program: exactly one day unlocks per day,
# you can't rush ahead, you build a streak, and you finish with a certificate.
#
# PASS_SCORE is the bar a day must clear to count as complete.
PASS_SCORE = 70

SPRINT = {
    "id": "sprint14",
    "title": "The 14-Day Speaking Sprint",
    "promise": "Speak English out loud every single day for two weeks. One day unlocks per day. No skipping, no drifting.",
    "days": [
        {"day": 1, "theme": "Breaking the Ice",
         "challenge": "Introduce yourself out loud to an imaginary stranger.",
         "phrases": ["Hi, I don't think we've met. I'm Ali.",
                     "Nice to meet you. How is your day going?",
                     "Are you here for the conference too?",
                     "What do you do for work?",
                     "It was really nice talking to you."],
         "conv": {"ai_role": "Sam, a friendly stranger at a conference coffee stand",
                  "setting": "A conference coffee break. You've never met before.",
                  "task": "Introduce yourself and find out one thing about the other person.",
                  "goals": ["Introduce yourself", "Ask them something about themselves", "Keep the conversation going for a moment"],
                  "useful": ["Hi, I don't think we've met.", "What brings you here?", "So, how long have you been coming to these?"]}},
        {"day": 2, "theme": "Talking About Yourself",
         "challenge": "Say three true sentences about your own life.",
         "phrases": ["I was born in Najaf, but I live in Baghdad now.",
                     "I work as a researcher at a university.",
                     "In my free time, I like reading and walking.",
                     "I have been learning English for two years.",
                     "My goal is to speak confidently at conferences."],
         "conv": {"ai_role": "Maya, a curious new neighbor",
                  "setting": "You've just moved in. Maya knocks to say hello.",
                  "task": "Tell her where you're from and what you do.",
                  "goals": ["Say where you're from", "Say what you do", "Ask them something back"],
                  "useful": ["I'm originally from…", "I work as a…", "What about you — what do you do?"]}},
        {"day": 3, "theme": "Everyday Small Talk",
         "challenge": "Talk about today's weather for 20 seconds.",
         "phrases": ["The weather is really nice today, isn't it?",
                     "Did you have a good weekend?",
                     "Traffic was terrible this morning.",
                     "I haven't seen you in a long time.",
                     "Let's catch up sometime this week."],
         "conv": {"ai_role": "Tom, a coworker you bump into in the hallway",
                  "setting": "Monday morning, by the coffee machine.",
                  "task": "Make small talk about the weekend, then say goodbye naturally.",
                  "goals": ["Ask about the weekend", "End the chat politely", "React naturally to what they say"],
                  "useful": ["Did you have a good weekend?", "Anyway, I should get going.", "Oh really? That sounds nice."]}},
        {"day": 4, "theme": "Asking for Help",
         "challenge": "Ask a stranger for directions, out loud.",
         "phrases": ["Excuse me, could you help me for a moment?",
                     "Sorry, could you repeat that more slowly?",
                     "I'm not sure I understand. Can you explain again?",
                     "Would you mind showing me how this works?",
                     "Thank you so much, I really appreciate it."],
         "conv": {"ai_role": "a librarian at the front desk",
                  "setting": "A public library. You can't find the printer.",
                  "task": "Ask for help finding the printer and understand the instructions.",
                  "goals": ["Ask for help politely", "Confirm you understood the instructions", "Thank them properly at the end"],
                  "useful": ["Excuse me, could you help me?", "Sorry, could you say that again?", "Thanks, that's really helpful."]}},
        {"day": 5, "theme": "Food & Restaurants",
         "challenge": "Order a full meal out loud, start to finish.",
         "phrases": ["Could we see the menu, please?",
                     "What would you recommend?",
                     "I'd like the chicken, but without onions.",
                     "Could we have the bill, please?",
                     "Everything was delicious, thank you."],
         "conv": {"ai_role": "Nora, a waiter at a busy restaurant",
                  "setting": "Dinner time. You're seated and ready to order.",
                  "task": "Order a meal, ask for one change, and ask for the bill.",
                  "goals": ["Order a meal", "Ask for the bill", "React to the food or the service"],
                  "useful": ["Could I have…", "Could we have the bill, please?", "This is really good, thank you."]}},
        {"day": 6, "theme": "Shopping & Money",
         "challenge": "Bargain for something out loud.",
         "phrases": ["How much does this cost?",
                     "Do you have this in a larger size?",
                     "That's a bit more than I wanted to spend.",
                     "Can I pay by card, or is it cash only?",
                     "I'd like to return this, please. Here is the receipt."],
         "conv": {"ai_role": "a market stall seller",
                  "setting": "A street market. You like a jacket but the price is high.",
                  "task": "Ask the price and try to negotiate a better one.",
                  "goals": ["Ask the price", "Try to negotiate", "Decide whether to buy it"],
                  "useful": ["How much is this?", "Could you do a better price?", "Alright, I'll take it."]}},
        {"day": 7, "theme": "Week One Review — Telling a Story",
         "challenge": "Tell the story of your last week in 30 seconds.",
         "phrases": ["Let me tell you what happened yesterday.",
                     "At first, I thought it was a small problem.",
                     "Then, suddenly, everything changed.",
                     "In the end, it worked out fine.",
                     "You should have seen the look on his face."],
         "conv": {"ai_role": "an old friend catching up over the phone",
                  "setting": "A phone call. You haven't spoken in months.",
                  "task": "Tell them one thing that happened to you this week.",
                  "goals": ["Start the story", "Get to how it ended", "React to hearing their side too"],
                  "useful": ["So, guess what happened…", "In the end…", "Wait, that happened to you too?"]}},
        {"day": 8, "theme": "Opinions & Agreeing",
         "challenge": "Give your opinion on something you read today.",
         "phrases": ["In my opinion, this is the better choice.",
                     "That's exactly what I was thinking.",
                     "I completely agree with you on that.",
                     "You make a really good point.",
                     "From my experience, it usually works well."],
         "conv": {"ai_role": "a colleague discussing a work decision",
                  "setting": "A short chat before a meeting.",
                  "task": "Share your opinion on a decision and react to theirs.",
                  "goals": ["Give your opinion", "Respond to their opinion", "Ask a follow-up question"],
                  "useful": ["In my opinion…", "That's a good point, but…", "What makes you say that?"]}},
        {"day": 9, "theme": "Disagreeing Politely",
         "challenge": "Disagree with a statement without being rude.",
         "phrases": ["I see your point, but I'm not sure I agree.",
                     "Actually, I have a slightly different view.",
                     "That may be true, however there is another side.",
                     "I understand, but have you considered this?",
                     "Let's agree to disagree on that one."],
         "conv": {"ai_role": "a classmate with a strong opinion on a group project",
                  "setting": "Planning a group project together.",
                  "task": "Disagree with their idea politely and suggest an alternative.",
                  "goals": ["Disagree without being rude", "Offer an alternative idea", "Keep the tone friendly, not tense"],
                  "useful": ["I see your point, but…", "What if we tried…?", "No hard feelings — just my two cents."]}},
        {"day": 10, "theme": "Phone Calls",
         "challenge": "Leave a voicemail out loud.",
         "phrases": ["Hello, this is Ali speaking. Is this a good time?",
                     "I'm calling about the appointment on Monday.",
                     "Sorry, the line is breaking up. Could you say that again?",
                     "Let me write that down. Go ahead.",
                     "Thanks for your time. I'll call you back tomorrow."],
         "conv": {"ai_role": "a receptionist at a dentist's office",
                  "setting": "A phone call to change an appointment.",
                  "task": "Explain why you're calling and agree on a new time.",
                  "goals": ["Explain the reason for calling", "Agree on a new time", "Confirm the details before hanging up"],
                  "useful": ["I'm calling about…", "Could we reschedule for…?", "So that's Tuesday at 3, right?"]}},
        {"day": 11, "theme": "Work & Job Talk",
         "challenge": "Explain your job to a child, out loud.",
         "phrases": ["I'm responsible for managing the whole project.",
                     "We're currently working on a new research paper.",
                     "Could we schedule a meeting for Thursday?",
                     "I'll send you the report by the end of the day.",
                     "Let me know if you need anything else from me."],
         "conv": {"ai_role": "a manager checking on a project's progress",
                  "setting": "A quick work check-in.",
                  "task": "Explain what you're working on and agree on a next step.",
                  "goals": ["Explain your current work", "Agree on a next step", "Ask if they need anything from you"],
                  "useful": ["I'm currently working on…", "I can have that ready by…", "Is there anything else you need from me?"]}},
        {"day": 12, "theme": "Travel & Directions",
         "challenge": "Describe the route from your home to the nearest shop.",
         "phrases": ["Excuse me, how do I get to the train station?",
                     "Is it within walking distance from here?",
                     "Go straight, then turn left at the traffic lights.",
                     "I think I'm lost. Could you show me on the map?",
                     "How long does it take to get there?"],
         "conv": {"ai_role": "a hotel receptionist",
                  "setting": "You're checking in and want to explore the city.",
                  "task": "Ask how to get to the city center and how long it takes.",
                  "goals": ["Ask for directions", "Ask how long it takes", "Thank them and confirm you understood"],
                  "useful": ["How do I get to…?", "How long does it take?", "Great, thank you, that's clear."]}},
        {"day": 13, "theme": "Explaining a Problem",
         "challenge": "Complain about a broken product, out loud.",
         "phrases": ["There seems to be a problem with my order.",
                     "It stopped working after only two days.",
                     "I'd like to speak to the manager, please.",
                     "I've already tried that, and it didn't help.",
                     "What can you do to fix this for me?"],
         "conv": {"ai_role": "Jordan, a customer service agent",
                  "setting": "A shop. Something you bought stopped working.",
                  "task": "Explain the problem and say what you want done about it.",
                  "goals": ["Explain the problem", "Say what you want", "Stay polite even if they push back"],
                  "useful": ["There's a problem with…", "I'd like a refund/replacement.", "I understand, but I'd still like this resolved."]}},
        {"day": 14, "theme": "Final Challenge — Speak for a Minute",
         "challenge": "Speak for one full minute about anything. No stopping.",
         "phrases": ["Two weeks ago, I was nervous about speaking English.",
                     "I practiced out loud every single day.",
                     "The hardest part for me was starting the conversation.",
                     "Now I can express my ideas much more clearly.",
                     "I'm going to keep practicing every day from now on."],
         "conv": {"ai_role": "a friend asking how the last two weeks went",
                  "setting": "A casual chat. They know you've been practicing English daily.",
                  "task": "Tell them what the 14 days were like and what you'll do next.",
                  "goals": ["Describe how the two weeks went", "Say what's next for you", "Thank them for listening"],
                  "useful": ["Honestly, at first…", "Going forward, I'm going to…", "Thanks for asking — it means a lot."]}},
    ],
}

# The second Sprint -- a retention feature for anyone who's already finished
# the Core Sprint and cleared out every Lesson/Shadow category. Same shape
# as SPRINT above (a day only needs "conv" here for the pre-chat briefing;
# the actual branching dialogue lives in SPRINT_CONVS_BIZ, content.py --
# same split as the Core Sprint uses). Gated behind "unlock_after" so it
# isn't just handed to a brand-new user on day one.
SPRINT_BIZ = {
    "id": "biz14",
    "title": "The 14-Day Business English Sprint",
    "promise": "Speak the English of meetings, emails, and negotiations — out loud, every day for two weeks.",
    "emoji": "💼",
    "unlock_after": "sprint14",
    "days": [
        {"day": 1, "theme": "Introducing Yourself at Work",
         "challenge": "Introduce yourself to a new colleague and describe your role in one breath.",
         "phrases": ["Hi, I'm Ali — I just joined the Marketing team.",
                     "I'll be working closely with Sales on the new campaign.",
                     "What does your role usually involve?",
                     "I'm really looking forward to working with everyone here.",
                     "Let me know if there's anything you need from my side."],
         "conv": {"ai_role": "Layla, a colleague from the Design team",
                  "setting": "Your first day at a new company. Layla stops by your desk to say hello.",
                  "task": "Introduce yourself, say your role, and ask about hers.",
                  "goals": ["Introduce yourself and your role", "Ask what she does", "End the conversation politely"],
                  "useful": ["I just joined the…", "What does your role involve?", "Great meeting you."]}},
        {"day": 2, "theme": "Talking About Your Job",
         "challenge": "Describe your day-to-day responsibilities to someone outside your company.",
         "phrases": ["I work as a project coordinator at a logistics company.",
                     "Most of my day is spent scheduling shipments and talking to clients.",
                     "The most challenging part is keeping everyone updated in real time.",
                     "I've been in this role for about a year and a half.",
                     "What I enjoy most is solving problems under pressure."],
         "conv": {"ai_role": "Yusuf, someone you meet at a family friend's dinner",
                  "setting": "A dinner party. Yusuf, who works in a different field, asks about your job.",
                  "task": "Explain what you do and what you find challenging or interesting about it.",
                  "goals": ["Say your job title", "Describe a typical task", "Say what you enjoy or find hard"],
                  "useful": ["I work as a…", "A typical day involves…", "What I find challenging is…"]}},
        {"day": 3, "theme": "Office Small Talk",
         "challenge": "Catch up with a coworker about a project for twenty seconds.",
         "phrases": ["Hey, how's the Hamid account coming along?",
                     "We're a bit behind, but it should be wrapped up by Friday.",
                     "Let me know if you need an extra pair of hands.",
                     "Actually, that would really help — thank you.",
                     "No problem, just send it my way whenever you're ready."],
         "conv": {"ai_role": "Noor, a coworker on the same floor",
                  "setting": "Monday morning by the coffee machine. Noor asks about a project you're both aware of.",
                  "task": "Give a quick honest update and offer or accept help naturally.",
                  "goals": ["Give a status update", "Mention a small problem", "Offer or accept help"],
                  "useful": ["It's coming along, but…", "We're a bit behind on…", "Let me know if you need a hand."]}},
        {"day": 4, "theme": "Scheduling a Meeting",
         "challenge": "Ask a colleague for their availability and agree on a time.",
         "phrases": ["Do you have some time this week to go over the report?",
                     "I'm free Tuesday afternoon or Wednesday morning.",
                     "Tuesday at 2 works well for me.",
                     "Should we book the small meeting room or just call?",
                     "Let's do a quick call — I'll send the invite now."],
         "conv": {"ai_role": "Karim, a colleague you need to meet with",
                  "setting": "An office chat thread. You need to schedule time to review a report together.",
                  "task": "Propose a meeting, agree on a time, and confirm how you'll meet.",
                  "goals": ["Ask for their availability", "Agree on a specific time", "Confirm the meeting format"],
                  "useful": ["Do you have time to…?", "I'm free on…", "Let's do a quick call/meeting."]}},
        {"day": 5, "theme": "Speaking Up in a Meeting",
         "challenge": "Give your opinion on an idea, politely, even if you partly disagree.",
         "phrases": ["Can I add something here?",
                     "I see the value in that, but I have one concern.",
                     "What if we tried a smaller version first?",
                     "That's a fair point — I hadn't thought of it that way.",
                     "I think we're aligned, then."],
         "conv": {"ai_role": "Dana, your team lead, presenting a plan in a meeting",
                  "setting": "A team meeting. Dana just proposed a plan you have one concern about.",
                  "task": "Politely raise your concern and suggest an alternative.",
                  "goals": ["Ask to add a point", "Raise your concern politely", "Suggest an alternative"],
                  "useful": ["Can I add something?", "I have one concern about…", "What if we…?"]}},
        {"day": 6, "theme": "Pitching an Idea",
         "challenge": "Explain a new idea to your team in three sentences.",
         "phrases": ["I'd like to propose something for next quarter.",
                     "The idea is to automate our weekly reporting.",
                     "It would save the team a few hours every week.",
                     "The main cost would be a short setup period.",
                     "I'd love to hear your thoughts."],
         "conv": {"ai_role": "the team, represented by Sami",
                  "setting": "A short team meeting. You have two minutes to pitch a new idea.",
                  "task": "Present the idea, mention its benefit, and invite feedback.",
                  "goals": ["State the idea clearly", "Mention one clear benefit", "Invite questions or feedback"],
                  "useful": ["I'd like to propose…", "This would save/help…", "I'd love to hear your thoughts."]}},
        {"day": 7, "theme": "A Client Check-in Call",
         "challenge": "Call a client to check on their satisfaction and next steps.",
         "phrases": ["Hi, this is Ali calling from Atlas Logistics — is now a good time?",
                     "I wanted to check in on how the shipment went.",
                     "Is there anything we could have done better?",
                     "Great to hear. What can we help with next?",
                     "I'll follow up by email with the details."],
         "conv": {"ai_role": "Mrs. Hana, a client",
                  "setting": "A phone call. You're checking in with a client after a recent order.",
                  "task": "Check on their experience and confirm the next step.",
                  "goals": ["Confirm it's a good time to talk", "Ask how the order/service went", "Confirm a next step"],
                  "useful": ["Is now a good time?", "I wanted to check in on…", "I'll follow up with…"]}},
        {"day": 8, "theme": "Clarifying an Email",
         "challenge": "Ask a colleague to clarify something confusing they wrote.",
         "phrases": ["I read your email, but I wasn't totally sure about one part.",
                     "When you say 'by the end of the week,' do you mean Friday?",
                     "Should I send this to the client directly, or through you?",
                     "Got it, that makes sense now.",
                     "Thanks for clearing that up."],
         "conv": {"ai_role": "Rania, a colleague who sent you a slightly unclear email",
                  "setting": "You just read an email from Rania and one part is unclear.",
                  "task": "Ask a clarifying question and confirm you understood the answer.",
                  "goals": ["Reference the email", "Ask a specific clarifying question", "Confirm you understood"],
                  "useful": ["I wasn't totally sure about…", "When you say…, do you mean…?", "Got it, that makes sense."]}},
        {"day": 9, "theme": "Handling Pushback",
         "challenge": "Respond calmly when a colleague disagrees with your idea.",
         "phrases": ["I understand your concern, but let me explain my thinking.",
                     "That's true, though I think the benefit outweighs the risk.",
                     "Would it help if we tested it on a small scale first?",
                     "I hear you — let's find a middle ground.",
                     "I appreciate you being upfront about this."],
         "conv": {"ai_role": "Omar, a colleague who disagrees with your proposal",
                  "setting": "A meeting. Omar just pushed back on an idea you proposed.",
                  "task": "Stay calm, explain your reasoning, and look for a compromise.",
                  "goals": ["Acknowledge their concern", "Explain your reasoning", "Suggest a compromise"],
                  "useful": ["I understand your concern, but…", "Would it help if…?", "Let's find a middle ground."]}},
        {"day": 10, "theme": "Negotiating a Deadline",
         "challenge": "Ask for more time on a project, professionally.",
         "phrases": ["I wanted to talk to you about the deadline for the report.",
                     "We've hit a small delay because of missing data.",
                     "Would it be possible to move it to next Wednesday?",
                     "I can send a partial draft by Friday in the meantime.",
                     "Thank you for understanding."],
         "conv": {"ai_role": "your manager, Farah",
                  "setting": "Your manager's office. A project deadline is at risk.",
                  "task": "Explain the delay and negotiate a new deadline.",
                  "goals": ["Explain the reason for the delay", "Propose a new deadline", "Offer something in the meantime"],
                  "useful": ["We've hit a delay because…", "Would it be possible to…?", "In the meantime, I can…"]}},
        {"day": 11, "theme": "Giving Feedback",
         "challenge": "Give a teammate one piece of constructive feedback.",
         "phrases": ["Do you have a minute for some quick feedback?",
                     "The report was really thorough — nice work.",
                     "One thing that could help is shortening the summary.",
                     "Would that be useful for next time?",
                     "Thanks for being open to it."],
         "conv": {"ai_role": "Salim, a teammate whose report you reviewed",
                  "setting": "After a team meeting. You want to give Salim quick, useful feedback.",
                  "task": "Give one positive comment and one improvement, kindly.",
                  "goals": ["Ask if it's a good time", "Give one specific positive point", "Give one specific improvement"],
                  "useful": ["Do you have a minute for feedback?", "One thing that could help is…", "Nice work on…"]}},
        {"day": 12, "theme": "Networking at an Event",
         "challenge": "Introduce yourself to a stranger at a conference and exchange contacts.",
         "phrases": ["Hi, I don't think we've met — I'm Ali, from Atlas Logistics.",
                     "What brings you to this conference?",
                     "That sounds fascinating — how did you get into that field?",
                     "Would you mind if we kept in touch?",
                     "Here's my card — feel free to reach out anytime."],
         "conv": {"ai_role": "Grace, another attendee at a conference",
                  "setting": "A conference networking break. You strike up a conversation with a stranger.",
                  "task": "Introduce yourself, learn about her work, and exchange contact details.",
                  "goals": ["Introduce yourself", "Ask what she does / why she's there", "Suggest staying in touch"],
                  "useful": ["I don't think we've met.", "What brings you here?", "Would you mind if we kept in touch?"]}},
        {"day": 13, "theme": "Job Interview Practice",
         "challenge": "Answer 'Tell me about yourself' in under thirty seconds.",
         "phrases": ["Sure — I've worked in logistics for about four years now.",
                     "My biggest strength is staying calm under pressure.",
                     "One thing I'm working on is delegating more.",
                     "I'm excited about this role because it combines planning and people.",
                     "Do you have any concerns about my background?"],
         "conv": {"ai_role": "Mr. Adel, an interviewer",
                  "setting": "A job interview. Mr. Adel asks you to introduce yourself.",
                  "task": "Give a short professional summary and answer a simple follow-up question.",
                  "goals": ["Give a brief professional summary", "Mention a strength", "Ask a question back at the end"],
                  "useful": ["I've worked in… for…", "My biggest strength is…", "Do you have any questions for me?"]}},
        {"day": 14, "theme": "Final Challenge — Present a Project Summary",
         "challenge": "Speak for one full minute summarizing a project, as if presenting to your team.",
         "phrases": ["Two weeks ago, talking business English out loud felt intimidating.",
                     "Now I can walk into a meeting and speak up with confidence.",
                     "The project wrapped up on time and under budget.",
                     "The biggest lesson was communicating early instead of waiting.",
                     "Going forward, I want to keep practicing this every week."],
         "conv": {"ai_role": "Layla, the colleague who welcomed you on Day 1",
                  "setting": "A wrap-up meeting. Layla asks how the project — and these two weeks — went.",
                  "task": "Summarize how the project went and what you'll do differently next time.",
                  "goals": ["Summarize the outcome", "Mention one lesson learned", "Say what's next"],
                  "useful": ["Overall, it went…", "The biggest lesson was…", "Going forward, I'm going to…"]}},
    ],
}

# Every Sprint program the app offers, keyed by id. Adding a third Sprint
# later is just: write its "days" list + its SPRINT_CONVS_* dict in
# content.py, then add one line here -- every endpoint below already reads
# through this registry instead of a hardcoded single SPRINT.
SPRINTS = {SPRINT["id"]: SPRINT, SPRINT_BIZ["id"]: SPRINT_BIZ}
SPRINT_CONVS_BY_SPRINT = {SPRINT["id"]: SPRINT_CONVS, SPRINT_BIZ["id"]: SPRINT_CONVS_BIZ}
SPRINT_DAY_BY_NUM_BY_SPRINT = {sid: {d["day"]: d for d in sdef["days"]} for sid, sdef in SPRINTS.items()}
DEFAULT_SPRINT_ID = SPRINT["id"]   # what every endpoint falls back to if sprint_id is omitted




# ----------------------------------------------------------------------
# 4. SECURITY HELPERS
# ----------------------------------------------------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    """
    Plain SMTP send — no third-party email package needed. Only called when
    EMAIL_CONFIGURED is True; callers should not call this otherwise.
    """
    msg = EmailMessage()
    msg["Subject"] = "Reset your SpeakPort password"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "We got a request to reset your SpeakPort password.\n\n"
        f"Reset it here (valid for 1 hour): {reset_link}\n\n"
        "If you didn't request this, you can safely ignore this email — "
        "your password won't change."
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def _sync_admin_status(user: User, session: Session):
    """
    Keeps the stored admin flag in EXACT lockstep with ADMIN_EMAIL.

    Runs on every authenticated request. If the user's email is in the admin
    list, they're granted admin (+ Pro, so you can test). If it is NOT, any
    admin flag they somehow have is REVOKED. This second half is the important
    one: it means a stale flag left in app.db from earlier testing can never
    keep granting admin to the wrong account.
    """
    should_be_admin = user.email.strip().lower() in ADMIN_EMAILS
    if should_be_admin and not user.is_admin:
        user.is_admin = True
        user.is_premium = True   # so you can test the Sprint straight away
        session.add(user); session.commit(); session.refresh(user)
    elif not should_be_admin and user.is_admin:
        # Actively demote anyone who isn't a listed admin.
        user.is_admin = False
        session.add(user); session.commit(); session.refresh(user)


def _sync_subscription_expiry(user: User, session: Session):
    """
    ZainCash payments buy a fixed 30-day window (pro_expires_at), unlike
    Paddle's recurring subscriptions. Checked on every request so access is
    revoked right on schedule without needing a background job. Admins are
    always exempt — they keep Pro regardless of any expiry date.
    """
    if user.is_admin:
        return
    if user.pro_expires_at and user.is_premium and dt.datetime.utcnow() > user.pro_expires_at:
        user.is_premium = False
        user.subscription_status = "canceled"
        session.add(user); session.commit(); session.refresh(user)


def get_current_user(request: Request, session: Session = Depends(get_session)) -> User:
    """Reads the 'Authorization: Bearer <token>' header and returns the user."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not logged in")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session")
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    _sync_admin_status(user, session)
    _sync_subscription_expiry(user, session)
    return user


# ----------------------------------------------------------------------
# 5. SIMPLE RATE LIMITER (slows down password-guessing attacks)
# ----------------------------------------------------------------------
_hits: dict[str, list[float]] = defaultdict(list)


def rate_limit(request: Request, key: str, limit: int, window: int):
    """Allow at most `limit` requests per `window` seconds, per IP + action."""
    ip = request.client.host if request.client else "unknown"
    bucket = f"{ip}:{key}"
    now = time.time()
    _hits[bucket] = [t for t in _hits[bucket] if now - t < window]
    if len(_hits[bucket]) >= limit:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts. Please wait a minute and try again.",
        )
    _hits[bucket].append(now)


# ----------------------------------------------------------------------
# 6. REQUEST SHAPES
# ----------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthIn(BaseModel):
    email: str
    password: str


class ForgotPasswordIn(BaseModel):
    email: str


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str


class GoogleAuthIn(BaseModel):
    credential: str  # the ID token Google's "Sign in with Google" button hands back


class ProfileIn(BaseModel):
    name: str = ""


class ChangePasswordIn(BaseModel):
    current_password: str = ""   # ignored when the account has no password yet
    new_password: str


class DeleteAccountIn(BaseModel):
    confirm_email: str


class PracticeIn(BaseModel):
    lesson_id: str
    phrase_index: int
    score: int
    transcript: str = ""


# ----------------------------------------------------------------------
# 7. ROUTES
# ----------------------------------------------------------------------
app = FastAPI(title="SpeakPort API")


def is_admin_user(user: User) -> bool:
    """
    THE security decision. Admin = your email is in ADMIN_EMAIL, full stop.
    We do NOT trust the stored is_admin flag here — that flag is just a cache
    for the UI. This way a stale flag in the database can never grant admin.
    """
    return user.email.strip().lower() in ADMIN_EMAILS


def public_user(user: User) -> dict:
    if user.is_admin:
        pro_provider = "admin"
    elif user.paddle_subscription_id:
        pro_provider = "paddle"
    elif user.zaincash_transaction_id:
        pro_provider = "zaincash"
    elif user.qicard_payment_id:
        pro_provider = "qicard"
    else:
        pro_provider = "none"
    return {
        "email": user.email,
        "name": user.name,
        "is_premium": user.is_premium,
        "is_admin": is_admin_user(user),
        "has_password": user.has_password,
        "member_since": user.created_at.isoformat(),
        "subscription_status": user.subscription_status,
        "pro_expires_at": user.pro_expires_at.isoformat() if user.pro_expires_at else None,
        "pro_provider": pro_provider,
        "goal": user.goal,
        "plan_tier": user.plan_tier,
    }


def _sync_admin(user: User, session: Session):
    """Kept for clarity at login; the real work is in _sync_admin_status."""
    _sync_admin_status(user, session)


@app.post("/api/register")
def register(data: AuthIn, request: Request, session: Session = Depends(get_session)):
    rate_limit(request, "register", limit=5, window=60)
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Please enter a valid email address.")
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    exists = session.exec(select(User).where(User.email == email)).first()
    if exists:
        raise HTTPException(400, "An account with this email already exists.")

    # Who gets admin: ONLY an email listed in ADMIN_EMAIL in your .env.
    #
    # There is deliberately no "first user becomes admin" shortcut. On a public
    # site that would mean the first stranger to sign up owns your admin panel.
    is_admin = email in ADMIN_EMAILS

    # Admins get Pro automatically, purely so you can test without clicking around.
    user = User(email=email, hashed_password=hash_password(data.password),
                is_admin=is_admin, is_premium=is_admin)
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"token": create_token(user.id), "user": public_user(user)}


@app.post("/api/login")
def login(data: AuthIn, request: Request, session: Session = Depends(get_session)):
    rate_limit(request, "login", limit=10, window=60)
    email = data.email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()
    # Same error whether email or password is wrong (don't leak which one).
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(401, "Wrong email or password.")
    _sync_admin(user, session)
    return {"token": create_token(user.id), "user": public_user(user)}


@app.post("/api/forgot-password")
def forgot_password(data: ForgotPasswordIn, request: Request,
                     session: Session = Depends(get_session)):
    """
    Always returns the same generic message whether or not that email has
    an account — so this endpoint can't be used to check who's registered.

    DEMO MODE (handing the reset link straight back in the response, instead
    of emailing it) is a LOCAL-ONLY convenience for testing before you've set
    up SMTP. It is deliberately disabled in production (detected the same way
    the rest of this app already tells local vs. production apart: whether
    DATABASE_URL is set — see section 1c). Handing out a working reset link
    to whoever asks for it, for ANY email, would be a live account-takeover
    hole on a real deployed site — anyone could "reset" anyone else's
    password just by knowing their email address.
    """
    rate_limit(request, "forgot-password", limit=5, window=300)
    email = data.email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()

    generic = {"sent": True,
               "message": "If an account exists for that email, a reset link has been sent."}

    if not user:
        return generic  # don't reveal whether the email exists

    token = secrets.token_urlsafe(32)
    reset = PasswordReset(
        user_id=user.id, token=token,
        expires_at=dt.datetime.utcnow() + dt.timedelta(hours=1),
    )
    session.add(reset)
    session.commit()

    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    reset_link = f"{base}/?reset={token}"

    if EMAIL_CONFIGURED:
        try:
            send_password_reset_email(user.email, reset_link)
        except Exception:
            # Don't leak SMTP errors to the client — just log server-side.
            print(f"[forgot-password] failed to send reset email to {user.email}")
        return generic

    if not IS_PRODUCTION:
        # Local dev only, and only when SMTP isn't set up yet: hand the link
        # straight back so you can still test the flow on your own machine.
        return {"sent": True, "message": "Email isn't configured yet — here's your reset link:",
                "demo_reset_link": reset_link}

    # Production, but SMTP isn't configured yet: log it server-side (for an
    # admin to retrieve from the Render logs if truly needed) and tell the
    # requester nothing beyond the generic message. Never expose the link to
    # whoever made the request — this is the fix for the account-takeover
    # issue above.
    print(f"[forgot-password] SMTP not configured — reset link for {user.email}: {reset_link}")
    return generic


@app.post("/api/reset-password")
def reset_password(data: ResetPasswordIn, request: Request,
                    session: Session = Depends(get_session)):
    rate_limit(request, "reset-password", limit=10, window=300)
    if len(data.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    reset = session.exec(select(PasswordReset).where(PasswordReset.token == data.token)).first()
    if not reset or reset.used or reset.expires_at < dt.datetime.utcnow():
        raise HTTPException(400, "This reset link is invalid or has expired. Please request a new one.")

    user = session.get(User, reset.user_id)
    if not user:
        raise HTTPException(400, "This reset link is invalid or has expired. Please request a new one.")

    user.hashed_password = hash_password(data.new_password)
    user.has_password = True   # works even for a Google-only account — this
                                # is how they'd pick up email+password login too
    reset.used = True
    session.add(user)
    session.add(reset)
    session.commit()
    _sync_admin(user, session)
    return {"token": create_token(user.id), "user": public_user(user)}


@app.get("/api/auth/config")
def auth_config():
    """
    Public, no login needed — tells the frontend whether to show "Sign in
    with Google", and which Client ID to use if so. Safe to expose: a
    Client ID is a public identifier, not a secret (see section 1c-3).
    """
    return {"google_client_id": GOOGLE_CLIENT_ID if GOOGLE_CONFIGURED else None}


@app.post("/api/auth/google")
def auth_google(data: GoogleAuthIn, request: Request, session: Session = Depends(get_session)):
    """
    "Sign in with Google" — verifies the ID token Google's button handed the
    frontend, then finds or creates a SpeakPort account for that email.

    Verification checks three things a forged/replayed token can't fake:
      1. Signature matches one of Google's current public keys (fetched
         live from Google the first time, cached after that).
      2. "aud" (audience) is OUR Client ID — proves this token was issued
         for THIS app, not for some other site's Google sign-in button.
      3. "email_verified" is true — Google only sets this once the person
         has actually confirmed that mailbox, so we can trust the email
         without sending our own verification link.
    """
    if not GOOGLE_CONFIGURED:
        raise HTTPException(503, "Google sign-in isn't set up yet.")
    rate_limit(request, "google-auth", limit=20, window=300)

    try:
        signing_key = _google_jwks_client.get_signing_key_from_jwt(data.credential)
    except jwt.PyJWTError as e:
        # Logged server-side only — never shown to the client — so we can
        # actually see WHY a real sign-in got rejected instead of guessing.
        print(f"[auth/google] couldn't get signing key: {type(e).__name__}: {e}")
        raise HTTPException(401, "Google sign-in failed — please try again.")
    except Exception as e:
        print(f"[auth/google] JWKS fetch failed: {type(e).__name__}: {e}")
        raise HTTPException(503, "Couldn't verify with Google right now — please try again in a moment.")

    try:
        payload = jwt.decode(data.credential, signing_key.key, algorithms=["RS256"],
                              audience=GOOGLE_CLIENT_ID)
    except jwt.PyJWTError as e:
        print(f"[auth/google] token verification failed: {type(e).__name__}: {e}")
        raise HTTPException(401, "Google sign-in failed — please try again.")

    # Checked separately from jwt.decode()'s own claim checks above, so this
    # works the same across older/newer PyJWT versions.
    if payload.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
        print(f"[auth/google] unexpected issuer: {payload.get('iss')!r}")
        raise HTTPException(401, "Google sign-in failed — please try again.")
    if not payload.get("email_verified"):
        raise HTTPException(401, "Your Google email isn't verified.")

    email = (payload.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(401, "Google didn't share an email address.")

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        # New account. This random password is never shown to anyone and
        # never used to sign in with — has_password=False is what actually
        # marks this account as Google-only; Account Settings shows "Set a
        # password" instead of "Change password" until they set a real one
        # (including via "Forgot password", which works for any account).
        is_admin = email in ADMIN_EMAILS
        user = User(email=email, hashed_password=hash_password(secrets.token_urlsafe(32)),
                    is_admin=is_admin, is_premium=is_admin, has_password=False,
                    name=(payload.get("name") or None))
        session.add(user)
        session.commit()
        session.refresh(user)
    else:
        _sync_admin(user, session)

    return {"token": create_token(user.id), "user": public_user(user)}


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not is_admin_user(user):
        raise HTTPException(403, "Admin access only.")
    return user


def require_max(user: User = Depends(get_current_user)) -> User:
    if not (user.is_premium and user.plan_tier == "max"):
        raise HTTPException(403, "This feature is available on the Max plan.")
    return user


@app.get("/api/me")
def me(user: User = Depends(get_current_user)):
    return public_user(user)


# ---- ACCOUNT SETTINGS ----
@app.post("/api/account/profile")
def update_profile(data: ProfileIn, request: Request,
                    user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    rate_limit(request, "account-profile", limit=20, window=300)
    name = data.name.strip()
    if len(name) > 60:
        raise HTTPException(400, "Name is too long (60 characters max).")
    user.name = name or None
    session.add(user)
    session.commit()
    session.refresh(user)
    return public_user(user)


class GoalIn(BaseModel):
    goal: str | None = None


@app.post("/api/account/goal")
def update_goal(data: GoalIn, user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    """Sets or clears the optional learning-goal hint (see GOAL_TAGS).
    Never gates anything -- just changes which existing content is
    flagged 'recommended' in /api/lessons and /api/scenarios."""
    goal = (data.goal or "").strip() or None
    if goal is not None and goal not in GOAL_IDS:
        raise HTTPException(400, f"Unknown goal. Choose one of: {', '.join(sorted(GOAL_IDS))}.")
    user.goal = goal
    session.add(user)
    session.commit()
    session.refresh(user)
    return public_user(user)


@app.post("/api/account/password")
def change_password(data: ChangePasswordIn, request: Request,
                     user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    Doubles as both "Change password" and "Set a password", depending on
    has_password. A Google-only account has no real current password to
    check, so that step is simply skipped — this is also how such an
    account picks up email+password login for the first time.
    """
    rate_limit(request, "account-password", limit=10, window=300)
    if len(data.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    if user.has_password and not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(401, "Current password is incorrect.")
    user.hashed_password = hash_password(data.new_password)
    user.has_password = True
    session.add(user)
    session.commit()
    return {"ok": True}


@app.post("/api/account/delete")
def delete_account(data: DeleteAccountIn, request: Request,
                    user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    Permanent, self-service account deletion. Confirmed by re-typing the
    account's own email rather than a password -- that works identically
    whether the account signs in with a password or with Google, and the
    point is only to stop an accidental click since reaching this endpoint
    already requires being signed in as this exact account.

    Note for the one payment rail this doesn't fully close out: an active
    Paddle subscription keeps renewing on Paddle's side until it's canceled
    there directly (or via Paddle's webhook) -- deleting the local account
    does not call Paddle's API. The frontend warns about this specific case
    before letting the delete go through. ZainCash/QiCard need no such
    warning since those are one-time purchases with a fixed expiry, not a
    recurring charge.
    """
    rate_limit(request, "account-delete", limit=5, window=300)
    if data.confirm_email.strip().lower() != user.email:
        raise HTTPException(400, "That email doesn't match this account.")

    uid = user.id
    for model in (Attempt, Enrollment, DayCompletion, DayConvDone, PasswordReset):
        for row in session.exec(select(model).where(model.user_id == uid)).all():
            session.delete(row)
    session.delete(user)
    session.commit()
    return {"deleted": True}


def _week_start() -> dt.datetime:
    """Monday 00:00 UTC of the current week — the leaderboard's reset point."""
    now = dt.datetime.utcnow()
    monday = now - dt.timedelta(days=now.weekday())
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)


def _mask_email(email: str) -> str:
    """Privacy-friendly fallback for anyone who hasn't set a display name —
    enough of a hint to recognize someone you know, not enough to fully
    expose a stranger's address on a leaderboard other users can see."""
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}" if domain else f"{local[:2]}***"


def _xp_earned_between(start: dt.datetime, end: dt.datetime | None, session: Session) -> dict[int, int]:
    """
    The shared XP formula (10/attempt + 5 bonus for 85%+, 100/completed
    Sprint day, 20/Voice Journal entry) scoped to a date range.
    /api/leaderboard always calls this with end=None (start of this week ->
    now); Speaking Leagues' weekly rollover calls it with an explicit end so
    it can score a week that has already finished, the same way.
    """
    attempt_q = select(Attempt).where(Attempt.created_at >= start)
    day_q = select(DayCompletion).where(DayCompletion.completed_at >= start)
    journal_q = select(JournalEntry).where(JournalEntry.created_at >= start)
    if end is not None:
        attempt_q = attempt_q.where(Attempt.created_at < end)
        day_q = day_q.where(DayCompletion.completed_at < end)
        journal_q = journal_q.where(JournalEntry.created_at < end)
    attempts = session.exec(attempt_q).all()
    days_done = session.exec(day_q).all()
    journal_entries = session.exec(journal_q).all()

    xp: dict[int, int] = defaultdict(int)
    for a in attempts:
        xp[a.user_id] += 10 + (5 if a.score >= 85 else 0)
    for d in days_done:
        xp[d.user_id] += 100
    for j in journal_entries:
        xp[j.user_id] += 20
    return xp


@app.get("/api/leaderboard")
def leaderboard(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    Weekly XP leaderboard, resets every Monday — a Pro perk, and a reason to
    keep practicing (and keep paying) even after finishing every lesson,
    Shadow category, and Sprint day. Uses the exact same XP formula as
    /api/progress (10/attempt + 5 bonus for 85%+, 100/completed Sprint day),
    just scoped to this week's rows instead of all-time.

    Admins are excluded from the rankings (they're not a real subscriber to
    compete against) but still see the real board if they check it.
    """
    if not user.is_premium:
        raise HTTPException(403, "The leaderboard is a Pro feature.")

    week_start = _week_start()
    ranked_users = session.exec(
        select(User).where(User.is_premium == True, User.is_admin == False)  # noqa: E712
    ).all()
    xp_by_user = _xp_earned_between(week_start, None, session)

    standings = sorted(
        ({"user_id": u.id, "name": u.name, "email": u.email, "xp": xp_by_user.get(u.id, 0)}
         for u in ranked_users),
        key=lambda r: r["xp"], reverse=True,
    )

    rows = []
    my_rank = None
    rank = 0
    for r in standings:
        if r["xp"] <= 0:
            continue   # no activity this week yet — leave them off the board entirely
        rank += 1
        if r["user_id"] == user.id:
            my_rank = rank
        if rank <= 20:
            rows.append({
                "rank": rank,
                "display": r["name"] or _mask_email(r["email"]),
                "xp": r["xp"],
                "is_me": r["user_id"] == user.id,
            })

    return {
        "week_start": week_start.isoformat(),
        "rows": rows,
        "my_rank": my_rank,
        "my_xp": xp_by_user.get(user.id, 0),
    }


# ----------------------------------------------------------------------
# 5b-2. GOAL PATHS — a lightweight content-surfacing hint, not a gate.
# ----------------------------------------------------------------------
# A user can optionally pick what they're learning English FOR (Account
# Settings). Nothing is ever hidden or locked based on it -- that would cut
# against this app's whole "no artificial limits" design. It just flags
# the existing Lessons/Conversations that best match as "recommended" so
# they surface first, and (for "exam") points at the two features best
# suited to IELTS/TOEFL-style speaking: Voice Journal and "Drill any
# topic", both of which train extended, unscripted, timed speech -- not
# just short scripted exchanges.
GOAL_IDS = {"travel", "work", "exam"}

GOAL_TAGS = {
    "travel": {"lessons": {"travel"}, "conversations": {"airport", "hotel", "directions"}},
    "work":   {"lessons": {"business", "interview"},
               "conversations": {"interview", "presentation", "negotiation", "complaint"}},
    "exam":   {"lessons": {"business", "interview"},
               "conversations": {"presentation", "negotiation"}},
}


# ----------------------------------------------------------------------
# 5c. SPEAKING LEAGUES — a Pro-exclusive, SpeakPort-specific twist on
# Duolingo's tiered weekly leagues.
# ----------------------------------------------------------------------
# The flat /api/leaderboard above pits every Pro user on the platform
# against each other, which stops feeling "winnable" once there are a lot
# of very active users. Leagues instead group you into a cohort of ~30
# similarly-active learners: finish in the top 5 of your cohort this week
# and you move up a tier; finish in the bottom 5 and you move down.
# Everyone else holds. Ranked by the exact same real-speaking-practice XP
# as the main leaderboard — this rewards actually practicing, not just
# grinding taps.
LEAGUE_TIERS = ["Bronze", "Silver", "Gold", "Diamond", "Speaker's Circle"]
LEAGUE_COHORT_SIZE = 30
LEAGUE_PROMOTE_COUNT = 5
LEAGUE_DEMOTE_COUNT = 5


def _league_cohort_chunks(user_ids: list[int], seed_key: str) -> list[list[int]]:
    """Deterministically splits a tier's members into cohorts of up to
    LEAGUE_COHORT_SIZE, reshuffled each week (seed_key includes the week)
    so cohort composition varies over time instead of always the same
    people. No cohort membership is ever stored -- it's recomputed from
    this pure function whenever it's needed."""
    order = sorted(user_ids)
    random.Random(seed_key).shuffle(order)
    return [order[i:i + LEAGUE_COHORT_SIZE] for i in range(0, len(order), LEAGUE_COHORT_SIZE)]


def _ensure_league_rollover(session: Session):
    """
    Runs the promotion/demotion pass for EVERY tier at once, but only once
    per week no matter how many requests come in — whichever request
    happens to be the first one made after Monday triggers it. This keeps
    every user's cohort for the new week computed from a consistent,
    already-settled set of tiers, rather than some users rolled over and
    others not yet (which would happen if this were done lazily per-user
    instead).
    """
    current_week = _week_start()
    current_week_str = current_week.isoformat()
    state = session.exec(select(LeagueRollupState)).first()
    if state is None:
        session.add(LeagueRollupState(last_rolled_week=current_week_str))
        session.commit()
        return   # first run ever -- nothing to roll over yet

    if state.last_rolled_week == current_week_str:
        return   # already processed this week

    prev_week_start = dt.datetime.fromisoformat(state.last_rolled_week)
    admin_ids = {u.id for u in session.exec(select(User).where(User.is_admin == True)).all()}  # noqa: E712
    members = session.exec(
        select(LeagueMembership).where(LeagueMembership.updated_week == state.last_rolled_week)
    ).all()
    members = [m for m in members if m.user_id not in admin_ids]

    if members:
        xp = _xp_earned_between(prev_week_start, current_week, session)
        by_tier: dict[int, list[LeagueMembership]] = defaultdict(list)
        for m in members:
            by_tier[m.tier].append(m)

        for tier, tier_members in by_tier.items():
            by_id = {m.user_id: m for m in tier_members}
            chunks = _league_cohort_chunks([m.user_id for m in tier_members],
                                            f"league-cohort:{state.last_rolled_week}")
            for chunk in chunks:
                ranked = sorted(chunk, key=lambda uid: xp.get(uid, 0), reverse=True)
                n = len(ranked)
                movable = n > LEAGUE_PROMOTE_COUNT + LEAGUE_DEMOTE_COUNT
                promote_n = LEAGUE_PROMOTE_COUNT if movable else 0
                demote_n = LEAGUE_DEMOTE_COUNT if movable else 0
                for i, uid in enumerate(ranked):
                    m = by_id[uid]
                    if i < promote_n:
                        m.tier = min(m.tier + 1, len(LEAGUE_TIERS) - 1)
                    elif i >= n - demote_n:
                        m.tier = max(m.tier - 1, 0)
                    m.updated_week = current_week_str
                    session.add(m)

    state.last_rolled_week = current_week_str
    session.add(state)
    session.commit()


@app.get("/api/leagues")
def get_leagues(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Speaking Leagues standings for the current user's cohort this week."""
    if not user.is_premium:
        raise HTTPException(403, "Speaking Leagues is a Pro feature.")
    if user.is_admin:
        raise HTTPException(400, "Admins don't compete in Speaking Leagues -- there's no real cohort for one.")

    _ensure_league_rollover(session)
    current_week = _week_start()
    current_week_str = current_week.isoformat()

    # Every Pro (non-admin) user is automatically "in" Leagues, the same
    # way the flat leaderboard already includes every Pro user without
    # requiring an explicit join -- so cohorts reflect the real Pro
    # population, not just whoever happened to open this screen first.
    pro_users = session.exec(
        select(User).where(User.is_premium == True, User.is_admin == False)  # noqa: E712
    ).all()
    existing = {m.user_id: m for m in session.exec(
        select(LeagueMembership).where(LeagueMembership.user_id.in_([u.id for u in pro_users]))
    ).all()}
    for u in pro_users:
        m = existing.get(u.id)
        if m is None:
            m = LeagueMembership(user_id=u.id, tier=0, updated_week=current_week_str)
            session.add(m)
            existing[u.id] = m
        elif m.updated_week != current_week_str:
            # Missed the batch rollover (e.g. had no XP to be ranked on
            # last week's pass) -- just carry them into the current week
            # at their existing tier.
            m.updated_week = current_week_str
            session.add(m)
    session.commit()
    membership = existing[user.id]
    session.refresh(membership)

    tier_user_ids = [uid for uid, m in existing.items()
                     if m.tier == membership.tier and m.updated_week == current_week_str]
    chunks = _league_cohort_chunks(tier_user_ids, f"league-cohort:{current_week_str}")
    cohort_ids = next((c for c in chunks if user.id in c), [user.id])

    xp = _xp_earned_between(current_week, None, session)
    cohort_users = {u.id: u for u in session.exec(select(User).where(User.id.in_(cohort_ids))).all()}

    standings = sorted(
        ({"user_id": uid,
          "xp": xp.get(uid, 0),
          "display": (cohort_users[uid].name or _mask_email(cohort_users[uid].email)) if uid in cohort_users else "?",
          "is_me": uid == user.id}
         for uid in cohort_ids),
        key=lambda r: r["xp"], reverse=True,
    )
    n = len(standings)
    movable = n > LEAGUE_PROMOTE_COUNT + LEAGUE_DEMOTE_COUNT
    promote_n = LEAGUE_PROMOTE_COUNT if movable else 0
    demote_n = LEAGUE_DEMOTE_COUNT if movable else 0
    for i, row in enumerate(standings):
        row["rank"] = i + 1
        row["zone"] = "promote" if i < promote_n else ("demote" if i >= n - demote_n else "safe")

    my_row = next((r for r in standings if r["is_me"]), None)

    return {
        "tier_index": membership.tier,
        "tier_name": LEAGUE_TIERS[membership.tier],
        "all_tiers": LEAGUE_TIERS,
        "is_top_tier": membership.tier == len(LEAGUE_TIERS) - 1,
        "is_bottom_tier": membership.tier == 0,
        "week_start": current_week_str,
        "cohort_size": n,
        "standings": standings,
        "my_rank": my_row["rank"] if my_row else None,
        "my_xp": my_row["xp"] if my_row else 0,
    }


@app.get("/api/lessons")
def list_lessons(user: User = Depends(get_current_user)):
    """Free lessons are always unlocked. Premium lessons need is_premium."""
    goal_tags = GOAL_TAGS.get(user.goal, {}) if user.goal else {}
    recommended_ids = goal_tags.get("lessons", set())
    out = []
    for lesson in LESSONS:
        locked = lesson["is_premium"] and not user.is_premium
        out.append({
            "id": lesson["id"],
            "title": lesson["title"],
            "level": lesson["level"],
            "is_premium": lesson["is_premium"],
            "locked": locked,
            # Only send the actual phrases if the user is allowed to see them.
            "phrases": [] if locked else lesson["phrases"],
            # A hint, never a gate -- see GOAL_TAGS.
            "recommended": lesson["id"] in recommended_ids,
        })
    return out


@app.get("/api/shadow")
def list_shadow_categories(user: User = Depends(get_current_user)):
    """
    Shadow Mode: connected-speech/rhythm practice. Same free/Pro locking
    pattern as /api/lessons — first two categories are free, the rest need
    is_premium. Content lives in content.py (SHADOW_CATEGORIES); no AI, no
    per-user cost, same as everything else in this app.
    """
    out = []
    for cat in SHADOW_CATEGORIES:
        locked = cat["is_premium"] and not user.is_premium
        out.append({
            "id": cat["id"],
            "title": cat["title"],
            "level": cat["level"],
            "focus": cat["focus"],
            "is_premium": cat["is_premium"],
            "locked": locked,
            "phrases": [] if locked else [p["en"] for p in cat["phrases"]],
            "tips": [] if locked else [p["tip"] for p in cat["phrases"]],
        })
    return out


# ----------------------------------------------------------------------
# 5b. DAILY PHRASE ROTATION — "new phrases today" banner
# ----------------------------------------------------------------------
# Lessons and Shadow Mode categories now carry a big pool (~100 phrases
# each) instead of just 5-15. Every /api/lessons or /api/shadow call still
# returns the WHOLE pool -- nothing is ever hidden or locked behind the
# rotation, so this never touches the practice flow, scoring, or spaced-
# repetition review (all of which index into the full pool by position,
# same as before).
#
# What rotates is purely a *notification*: each day, PHRASE_ROTATION_SIZE
# phrases per unit are marked "featured/new" so there's always something
# fresh to point the user toward. The rotation is a pure function of the
# calendar date (no DB writes, same for every user), so it needs no new
# tables -- only one nullable column on User to remember whether *this*
# user has already seen *today's* batch (so the banner doesn't nag on
# every page load).
PHRASE_ROTATION_SIZE = 20
PHRASE_ROTATION_EPOCH = dt.date(2026, 1, 1)   # arbitrary fixed reference point


def _phrase_rotation_window(pool_size: int, unit_seed: str, today: dt.date) -> list[int]:
    """
    Which phrase indices (into the full pool) are "featured" today.

    The pool is split into ceil(pool_size / PHRASE_ROTATION_SIZE) windows.
    One window advances into view every 24h. Once every window in a cycle
    has been shown once, the pool's shuffle order is regenerated (a new
    cycle_number seeds a fresh random.Random) -- same phrases, new order --
    so the repeat isn't an obvious, predictable loop.
    """
    if pool_size <= 0:
        return []
    days_elapsed = (today - PHRASE_ROTATION_EPOCH).days
    cycle_len = max(1, -(-pool_size // PHRASE_ROTATION_SIZE))  # ceil division
    cycle_number = days_elapsed // cycle_len
    day_in_cycle = days_elapsed % cycle_len
    order = list(range(pool_size))
    random.Random(f"{unit_seed}:{cycle_number}").shuffle(order)
    start = day_in_cycle * PHRASE_ROTATION_SIZE
    return order[start:start + PHRASE_ROTATION_SIZE]


def _phrases_new_today(today: dt.date | None = None) -> dict:
    """Everything needed to power the dashboard's 'new phrases today' banner."""
    today = today or dt.date.today()
    total = 0
    units = []
    for lesson in LESSONS:
        idxs = _phrase_rotation_window(len(lesson["phrases"]), f"lesson:{lesson['id']}", today)
        total += len(idxs)
        units.append({"kind": "lesson", "id": lesson["id"], "title": lesson["title"], "new_count": len(idxs)})
    for cat in SHADOW_CATEGORIES:
        idxs = _phrase_rotation_window(len(cat["phrases"]), f"shadow:{cat['id']}", today)
        total += len(idxs)
        units.append({"kind": "shadow", "id": cat["id"], "title": cat["title"], "new_count": len(idxs)})
    return {"today": today.isoformat(), "total_new": total, "units": units}


@app.get("/api/phrases/whats-new")
def phrases_whats_new(user: User = Depends(get_current_user)):
    """
    has_new is False once this user has already seen today's batch (tracked
    via last_seen_phrase_day), so the banner shows once per day rather than
    on every single dashboard load.
    """
    info = _phrases_new_today()
    already_seen = user.last_seen_phrase_day == info["today"]
    return {**info, "has_new": not already_seen}


@app.post("/api/phrases/whats-new/seen")
def phrases_whats_new_seen(user: User = Depends(get_current_user),
                           session: Session = Depends(get_session)):
    """Marks today's rotation as seen -- the banner won't show again until tomorrow's batch."""
    user.last_seen_phrase_day = dt.date.today().isoformat()
    session.add(user)
    session.commit()
    return {"ok": True}


@app.get("/api/phrases/spotlight")
def phrase_spotlight(user: User = Depends(get_current_user)):
    """
    Daily Spotlight Phrase — a Pro-exclusive, EWA-inspired bite-sized daily
    habit hook: one hand-cycled phrase, front and center. Distinct from the
    generic "N new phrases today" rotation banner (which is available to
    everyone and just reports a count) -- this is a premium, single-phrase
    highlight. Cycles through all 9 units (5 Lessons + 4 Shadow categories)
    one per day, then spotlights the FIRST phrase of that unit's featured
    rotation window for today (so it's always one of today's "new" ones).
    """
    if not user.is_premium:
        raise HTTPException(403, "The Daily Spotlight is a Pro feature.")

    today = dt.date.today()
    units = [("lesson", l["id"], l["title"], l["phrases"]) for l in LESSONS] + \
            [("shadow", c["id"], c["title"], c["phrases"]) for c in SHADOW_CATEGORIES]
    day_index = (today - PHRASE_ROTATION_EPOCH).days % len(units)
    kind, unit_id, unit_title, phrases = units[day_index]

    idxs = _phrase_rotation_window(len(phrases), f"{kind}:{unit_id}", today)
    phrase_index = idxs[0] if idxs else 0
    raw = phrases[phrase_index]
    en = raw if kind == "lesson" else raw["en"]
    ar = LESSON_TRANSLATIONS.get(en, "") if kind == "lesson" else raw.get("ar", "")
    tip = "" if kind == "lesson" else raw.get("tip", "")

    return {
        "kind": kind,
        "unit_id": unit_id,
        "unit_title": unit_title,
        "phrase_index": phrase_index,
        "en": en,
        "ar": ar,
        "tip": tip,
        "date": today.isoformat(),
    }


# ---- Voice Journal (Pro): a daily 60-second unscripted spoken prompt ----
def _journal_streak(user_id: int, session: Session) -> int:
    """
    Same "consecutive days ending today or yesterday" walk /api/progress
    uses for the main practice streak, but over JournalEntry.entry_date --
    Voice Journal is its own daily habit (reflect on your day out loud),
    tracked separately from lesson/Shadow practice.
    """
    rows = session.exec(select(JournalEntry).where(JournalEntry.user_id == user_id)).all()
    active_days = {dt.date.fromisoformat(r.entry_date) for r in rows}
    today = dt.date.today()
    streak = 0
    cursor = today if today in active_days else (today - dt.timedelta(days=1))
    while cursor in active_days:
        streak += 1
        cursor -= dt.timedelta(days=1)
    return streak


_WORD_RE = re.compile(r"[a-zA-Z']+")


def _journal_tips(transcript: str, hint_words: list[str]) -> list[dict]:
    """
    Deterministic, fully offline feedback for a free-form transcript with no
    fixed target sentence to compare against. Up to two grammar tips (a
    curated, finite catch of the classic "regularized irregular verb" ESL
    mistake -- "drinked" for "drank" -- see IRREGULAR_VERB_MISTAKES) take
    priority; otherwise a positive nudge if they used one of the prompt's
    suggested connector words; otherwise plain encouragement. Never claims
    to be a general grammar checker -- just this one well-known, catchable
    pattern.
    """
    words = _WORD_RE.findall(transcript.lower())
    mistakes: list[tuple[str, str, str]] = []
    seen = set()
    for w in words:
        if w in IRREGULAR_VERB_MISTAKES and w not in seen:
            seen.add(w)
            correct, base = IRREGULAR_VERB_MISTAKES[w]
            mistakes.append((w, correct, base))
        if len(mistakes) >= 2:
            break

    if mistakes:
        return [{"kind": "grammar", "wrong_word": wrong,
                 "text_en": f'Tip: past tense of "{base}" is "{correct}", not "{wrong}".',
                 "text_ar": f'ملاحظة: صيغة الماضي لفعل "{base}" هي "{correct}"، وليست "{wrong}".'}
                for wrong, correct, base in mistakes]

    lower_transcript = transcript.lower()
    used_hint = next((h for h in hint_words if h.lower() in lower_transcript), None)
    if used_hint:
        return [{"kind": "encouragement",
                 "text_en": f'Nice — you used "{used_hint}" just like the prompt suggested!',
                 "text_ar": f'أحسنت — استخدمت "{used_hint}" تماماً كما اقترح التمرين!'}]

    return [{"kind": "encouragement",
             "text_en": "Good effort — keep talking every day, it adds up fast.",
             "text_ar": "مجهود جيد — استمر بالتحدث كل يوم، والنتيجة تتراكم بسرعة."}]


def _today_journal_prompt(today: dt.date) -> dict:
    idx = (today - PHRASE_ROTATION_EPOCH).days % len(JOURNAL_PROMPTS)
    return JOURNAL_PROMPTS[idx]


@app.get("/api/journal/today")
def journal_today(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if not user.is_premium:
        raise HTTPException(403, "Voice Journal is a Pro feature.")

    today = dt.date.today()
    prompt = _today_journal_prompt(today)
    existing = session.exec(
        select(JournalEntry).where(JournalEntry.user_id == user.id,
                                    JournalEntry.entry_date == today.isoformat())
    ).first()

    today_entry = None
    if existing:
        today_entry = {
            "word_count": existing.word_count,
            "duration_sec": existing.duration_sec,
            "tips": _journal_tips(existing.transcript, prompt["hint_words"]),
        }

    return {
        "prompt_en": prompt["en"],
        "prompt_ar": prompt["ar"],
        "hint_words": prompt["hint_words"],
        "already_done_today": existing is not None,
        "journal_streak": _journal_streak(user.id, session),
        "today_entry": today_entry,
    }


@app.post("/api/journal/entry")
def journal_entry(payload: dict, user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    if not user.is_premium:
        raise HTTPException(403, "Voice Journal is a Pro feature.")

    transcript = (payload.get("transcript") or "").strip()
    duration_sec = max(0, int(payload.get("duration_sec") or 0))
    if not transcript:
        raise HTTPException(400, "No speech was recognized -- try again.")

    today = dt.date.today()
    prompt = _today_journal_prompt(today)
    existing = session.exec(
        select(JournalEntry).where(JournalEntry.user_id == user.id,
                                    JournalEntry.entry_date == today.isoformat())
    ).first()

    if existing:
        return {
            "already_existed": True,
            "xp_earned": 0,
            "journal_streak": _journal_streak(user.id, session),
            "word_count": existing.word_count,
            "duration_sec": existing.duration_sec,
            "tips": _journal_tips(existing.transcript, prompt["hint_words"]),
        }

    word_count = len(_WORD_RE.findall(transcript))
    row = JournalEntry(user_id=user.id, entry_date=today.isoformat(), prompt_en=prompt["en"],
                       transcript=transcript, duration_sec=duration_sec, word_count=word_count)
    session.add(row)
    session.commit()

    return {
        "already_existed": False,
        "xp_earned": 20,
        "journal_streak": _journal_streak(user.id, session),
        "word_count": word_count,
        "duration_sec": duration_sec,
        "tips": _journal_tips(transcript, prompt["hint_words"]),
    }


@app.post("/api/practice")
def save_practice(data: PracticeIn, user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    # data.lesson_id is either a real lesson ID or a Shadow Mode category ID
    # (both live in the same string field — Shadow attempts count toward the
    # same total-attempts/streak/best-score stats as lesson practice).
    lesson = LESSON_BY_ID.get(data.lesson_id)
    shadow_cat = SHADOW_BY_ID.get(data.lesson_id)
    if not lesson and not shadow_cat:
        raise HTTPException(404, "Lesson not found.")
    is_premium_item = lesson["is_premium"] if lesson else shadow_cat["is_premium"]
    if is_premium_item and not user.is_premium:
        raise HTTPException(403, "This is a premium lesson.")
    score = max(0, min(100, int(data.score)))
    attempt = Attempt(
        user_id=user.id, lesson_id=data.lesson_id,
        phrase_index=data.phrase_index, score=score,
        transcript=data.transcript[:500],
    )
    session.add(attempt)
    session.commit()

    # Every lesson/Shadow attempt also feeds the spaced-repetition schedule --
    # unconditionally, even for free users, so a full review history already
    # exists the moment someone upgrades (nothing to backfill).
    kind = "lesson" if lesson else "shadow"
    item_id = f"{kind}:{data.lesson_id}:{data.phrase_index}"
    _upsert_review_item(user.id, item_id, score, session)

    return {"saved": True, "score": score}


REVIEW_BOX_INTERVALS = {1: 1, 2: 3, 3: 7, 4: 14, 5: 30}   # box -> days until due again


def _upsert_review_item(user_id: int, item_id: str, score: int, session: Session):
    """
    Reschedules one phrase's spot in its Leitner box after a practice
    attempt. A strong score (>=85) advances a box (a longer wait before it's
    due again); anything weaker resets to box 1 (due again very soon). The
    first attempt at a phrase creates its row here.
    """
    existing = session.exec(
        select(ReviewItem).where(ReviewItem.user_id == user_id, ReviewItem.item_id == item_id)
    ).first()
    box = min((existing.box + 1), 5) if (existing and score >= 85) else 1
    next_at = dt.datetime.utcnow() + dt.timedelta(days=REVIEW_BOX_INTERVALS[box])

    if existing:
        existing.box = box
        existing.next_review_at = next_at
        existing.last_score = score
        existing.updated_at = dt.datetime.utcnow()
        session.add(existing)
    else:
        session.add(ReviewItem(user_id=user_id, item_id=item_id, box=box,
                                next_review_at=next_at, last_score=score))
    session.commit()


def _resolve_review_item(item_id: str) -> dict | None:
    """
    Turns a stored item_id back into real, displayable phrase content.
    Returns None if the source lesson/category or phrase index no longer
    exists (e.g. content.py was edited after this row was created) so the
    caller can just skip it rather than error.
    """
    kind, _, rest = item_id.partition(":")
    source_id, _, idx_str = rest.rpartition(":")
    try:
        idx = int(idx_str)
    except ValueError:
        return None

    if kind == "lesson":
        lesson = LESSON_BY_ID.get(source_id)
        if not lesson or idx >= len(lesson["phrases"]):
            return None
        return {"item_id": item_id, "source_id": source_id, "phrase_index": idx,
                "en": lesson["phrases"][idx], "tip": "", "source_title": lesson["title"]}

    if kind == "shadow":
        cat = SHADOW_BY_ID.get(source_id)
        if not cat or idx >= len(cat["phrases"]):
            return None
        phrase = cat["phrases"][idx]
        return {"item_id": item_id, "source_id": source_id, "phrase_index": idx,
                "en": phrase["en"], "tip": phrase.get("tip", ""), "source_title": cat["title"]}

    return None


def _resolve_attempt_target(lesson_id: str, phrase_index: int) -> str | None:
    """Same lesson-or-Shadow-category lookup /api/practice already does,
    just returning the plain English text instead of validating a save."""
    lesson = LESSON_BY_ID.get(lesson_id)
    if lesson:
        return lesson["phrases"][phrase_index] if phrase_index < len(lesson["phrases"]) else None
    cat = SHADOW_BY_ID.get(lesson_id)
    if cat:
        return cat["phrases"][phrase_index]["en"] if phrase_index < len(cat["phrases"]) else None
    return None


# ---- Weak-word tracking: the exact per-word "weak/ok" signal Pronunciation
# Focus already shows live on a single attempt (see wordWeakPoints() in the
# frontend), ported to Python so it can be aggregated across a learner's
# ENTIRE attempt history -- "which words do I keep mispronouncing" instead
# of just "how did I do on this one phrase". Same normalize/levenshtein/
# similarity math, same 60% weak threshold, so the two views never disagree.
def _normalize_word(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    d = [[0] * (n + 1) for _ in range(m + 1)]
    for j in range(n + 1):
        d[0][j] = j
    for i in range(m + 1):
        d[i][0] = i
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
    return d[m][n]


def _word_similarity(target: str, said: str) -> int:
    t, s = _normalize_word(target), _normalize_word(said)
    if not s:
        return 0
    dist = _levenshtein(t, s)
    return round((1 - dist / max(len(t), len(s), 1)) * 100)


def _word_weak_points(target: str, heard_text: str) -> list[dict]:
    target_words = [w for w in target.split() if w]
    heard_words = [w for w in _normalize_word(heard_text).split() if w]
    out = []
    for tw in target_words:
        t_clean = _normalize_word(tw)
        best = 0
        for hw in heard_words:
            best = max(best, _word_similarity(t_clean, hw))
        out.append({"word": tw, "weak": best < 60})
    return out


@app.get("/api/progress/weak-words")
def weak_words(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    "Words to work on" -- a Pro feature, matching the live per-word
    Pronunciation Focus feedback it's built from. Walks every attempt that
    has a saved transcript, resolves its target phrase, and tallies how
    often each word came back flagged "weak". Only surfaces words seen at
    least twice AND weak at least half the time, so one rough take doesn't
    brand a word a problem.
    """
    if not user.is_premium:
        raise HTTPException(403, "Weak-word tracking is a Pro feature.")

    attempts = session.exec(
        select(Attempt).where(Attempt.user_id == user.id, Attempt.transcript != "")
    ).all()

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])   # word -> [weak, total]
    analyzed = 0
    for a in attempts:
        target = _resolve_attempt_target(a.lesson_id, a.phrase_index)
        if not target:
            continue
        analyzed += 1
        for wp in _word_weak_points(target, a.transcript):
            key = _normalize_word(wp["word"])
            if not key:
                continue
            counts[key][1] += 1
            if wp["weak"]:
                counts[key][0] += 1

    words = [
        {"word": word, "weak_count": weak, "total_count": total,
         "weak_ratio": round(weak / total, 2)}
        for word, (weak, total) in counts.items()
        if total >= 2 and weak / total >= 0.5
    ]
    words.sort(key=lambda w: (w["weak_count"], w["weak_ratio"]), reverse=True)

    return {"words": words[:10], "attempts_analyzed": analyzed}


@app.get("/api/review/due")
def review_due(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    Up to 20 phrases due for spaced-repetition review right now -- a Pro
    perk, and a reason to come back once every Lesson/Shadow category has
    already been finished once. due_count is the true total due (which may
    exceed the 20 actually returned), so the dashboard badge stays accurate
    even though one review session is capped at a manageable size.
    """
    if not user.is_premium:
        raise HTTPException(403, "Spaced-repetition review is a Pro feature.")

    now = dt.datetime.utcnow()
    due_rows = session.exec(
        select(ReviewItem)
        .where(ReviewItem.user_id == user.id, ReviewItem.next_review_at <= now)
        .order_by(ReviewItem.next_review_at)
    ).all()

    items = []
    for row in due_rows:
        resolved = _resolve_review_item(row.item_id)
        if resolved:
            items.append(resolved)
        if len(items) >= 20:
            break

    return {"due_count": len(due_rows), "items": items}


@app.get("/api/progress/history")
def progress_history(user: User = Depends(get_current_user),
                     session: Session = Depends(get_session)):
    """
    Daily average score for the last 14 active days — powers the Pro
    progress graph ("look how far you've come"). Free users get the
    basic stats from /api/progress; this richer view is a Pro perk.
    """
    if not user.is_premium:
        raise HTTPException(403, "The progress graph is a Pro feature.")
    attempts = session.exec(
        select(Attempt).where(Attempt.user_id == user.id).order_by(Attempt.created_at)
    ).all()
    by_day: dict[str, list[int]] = {}
    for a in attempts:
        key = a.created_at.date().isoformat()
        by_day.setdefault(key, []).append(a.score)

    days = sorted(by_day)[-14:]   # last 14 active days
    points = [{"date": d, "avg_score": round(sum(by_day[d]) / len(by_day[d])),
              "attempts": len(by_day[d])} for d in days]

    # Simple trend: compare the average of the first half vs the second half.
    trend = "steady"
    if len(points) >= 4:
        mid = len(points) // 2
        first_avg = sum(p["avg_score"] for p in points[:mid]) / mid
        second_avg = sum(p["avg_score"] for p in points[mid:]) / (len(points) - mid)
        if second_avg - first_avg >= 4:
            trend = "improving"
        elif first_avg - second_avg >= 4:
            trend = "declining"

    return {"points": points, "trend": trend}


@app.get("/api/progress")
def progress(user: User = Depends(get_current_user),
             session: Session = Depends(get_session)):
    """
    Progress + a real daily-practice streak, computed from attempt history.

    The streak is the number of consecutive days (ending today or yesterday)
    on which the learner practised at least once. This is the single biggest
    habit driver in a language app — "don't break the chain."
    """
    attempts = session.exec(select(Attempt).where(Attempt.user_id == user.id)).all()
    best: dict[str, int] = {}
    scores = []
    active_days = set()
    for a in attempts:
        best[a.lesson_id] = max(best.get(a.lesson_id, 0), a.score)
        scores.append(a.score)
        active_days.add(a.created_at.date())

    # XP: a simple, transparent points system (Duolingo-style), computed on
    # the fly from existing data — same approach as the streak above, so
    # there's no new column to migrate or keep in sync. 10 XP per practice
    # attempt (lesson or Shadow Mode), +5 bonus for a strong (85%+) attempt,
    # and 100 XP per completed Sprint day (a bigger milestone).
    days_completed = session.exec(
        select(DayCompletion).where(DayCompletion.user_id == user.id)
    ).all()
    journal_entries_count = session.exec(
        select(JournalEntry).where(JournalEntry.user_id == user.id)
    ).all()
    xp = (len(attempts) * 10 + sum(5 for a in attempts if a.score >= 85)
          + len(days_completed) * 100 + len(journal_entries_count) * 20)

    today = dt.date.today()

    # Streak Shield — a Pro-exclusive, always-on perk (SpeakPort's take on
    # Duolingo's streak freeze). Free users' streaks are untouched below:
    # a single missed day just breaks the chain, same as always. Pro users
    # get exactly one missed day auto-protected whenever it happens (not a
    # stockpiled/spendable currency — just a standing subscriber benefit),
    # recorded permanently in StreakShieldUse so it only ever covers a
    # given date once and stays auditable.
    shield_just_saved = False
    if user.is_premium and active_days:
        latest_active = max(active_days)
        gap_days = (today - latest_active).days
        if gap_days == 2:   # exactly one day missing between last practice and today
            missed_date = (latest_active + dt.timedelta(days=1)).isoformat()
            already_shielded = session.exec(
                select(StreakShieldUse).where(StreakShieldUse.user_id == user.id,
                                               StreakShieldUse.shielded_date == missed_date)
            ).first()
            if not already_shielded:
                session.add(StreakShieldUse(user_id=user.id, shielded_date=missed_date))
                session.commit()
                shield_just_saved = True
    if user.is_premium:
        shielded = session.exec(select(StreakShieldUse).where(StreakShieldUse.user_id == user.id)).all()
        for row in shielded:
            active_days.add(dt.date.fromisoformat(row.shielded_date))

    # Daily streak: walk back day by day from today while each day was
    # active (a day protected by the Streak Shield above counts as active).
    streak = 0
    # Allow the streak to be "alive" if they practised today OR yesterday
    # (so it doesn't reset the instant midnight passes before they log in).
    cursor = today if today in active_days else (today - dt.timedelta(days=1))
    while cursor in active_days:
        streak += 1
        cursor -= dt.timedelta(days=1)

    # Longest streak ever, for a sense of personal best.
    longest = 0
    if active_days:
        ordered = sorted(active_days)
        run = 1; longest = 1
        for i in range(1, len(ordered)):
            if (ordered[i] - ordered[i-1]).days == 1:
                run += 1
            else:
                run = 1
            longest = max(longest, run)

    return {
        "total_attempts": len(attempts),
        "best_by_lesson": best,
        "streak": streak,
        "longest_streak": longest,
        "days_practiced": len(active_days),
        "practiced_today": today in active_days,
        "avg_score": round(sum(scores) / len(scores)) if scores else 0,
        "best_score": max(scores) if scores else 0,
        "xp": xp,
        "streak_shield_active": user.is_premium,
        "streak_shield_just_saved": shield_just_saved,
    }


@app.get("/api/badges")
def badges_data(user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    """
    Extra numbers (beyond /api/progress) needed to unlock achievement
    badges. Badge titles/descriptions/icons live in the frontend — this
    just supplies the raw counts, so thresholds stay easy to tune in one
    place without touching the backend.
    """
    attempts = session.exec(select(Attempt).where(Attempt.user_id == user.id)).all()
    shadow_attempts = sum(1 for a in attempts if a.lesson_id in SHADOW_BY_ID)
    perfect_scores = sum(1 for a in attempts if a.score == 100)
    sprint_state = _sprint_state(user, DEFAULT_SPRINT_ID, session)
    return {
        "shadow_attempts": shadow_attempts,
        "perfect_scores": perfect_scores,
        "sprint_finished": bool(sprint_state.get("finished")),
    }


class UpgradeIn(BaseModel):
    tier: str = "pro"


@app.post("/api/upgrade")
def upgrade(data: UpgradeIn = UpgradeIn(), user: User = Depends(get_current_user),
            session: Session = Depends(get_session)):
    """
    DEMO-MODE ONLY. While no real payment provider is configured, this
    instantly grants Pro (or Max) so you can test the whole app without a
    Paddle account. The moment PADDLE_* env vars are set (production), this
    shortcut is disabled — real Pro access then comes ONLY from a signed
    payment webhook (see /api/billing/webhook below). This prevents anyone
    from just calling this endpoint directly to get Pro for free.
    """
    if PADDLE_CONFIGURED or ZAINCASH_CONFIGURED or QICARD_CONFIGURED:
        raise HTTPException(403, "Real payments are live — use the Upgrade "
                                 "button to check out.")
    user.is_premium = True
    user.plan_tier = data.tier if data.tier in ("pro", "max") else "pro"
    session.add(user)
    session.commit()
    return {"is_premium": True}


@app.get("/api/billing/config")
def billing_config(user: User = Depends(get_current_user)):
    """
    Tells the frontend how to open checkout, and which provider(s) are live.
    Only ever exposes PUBLIC values (safe in the browser) — secret keys
    never leave the server.

    Two DIFFERENT kinds of provider can be configured at once:
      - Paddle: card-based, uses its own overlay SDK — mutually exclusive
        with the local providers below (Paddle wins if somehow both are set,
        since it targets a different audience — customers outside Iraq).
      - Local Iraqi rails (ZainCash, QiCard): both can be configured
        SIMULTANEOUSLY, since they reach different customers (ZainCash =
        Zain mobile wallet; QiCard = Qi Card holders via Rafidain/Rasheed
        Bank). The frontend shows one "Pay with X" button per local
        provider that's configured.
    """
    local_providers = []
    if ZAINCASH_CONFIGURED:
        local_providers.append({"id": "zaincash", "label": "ZainCash"})
    if QICARD_CONFIGURED:
        local_providers.append({"id": "qicard", "label": "Qi Card / SuperQi"})

    provider = "paddle" if PADDLE_CONFIGURED else (local_providers[0]["id"] if local_providers else "none")
    return {
        "configured": provider != "none",
        "provider": provider,
        "local_providers": local_providers,
        "client_token": PADDLE_CLIENT_TOKEN if PADDLE_CONFIGURED else "",
        "price_id": PADDLE_PRICE_ID if PADDLE_CONFIGURED else "",
        # Empty string means "not offered yet" -- the frontend only shows an
        # annual option to Paddle customers once you've created a second
        # Price in your Paddle dashboard and set PADDLE_PRICE_ID_ANNUAL.
        "price_id_annual": PADDLE_PRICE_ID_ANNUAL if PADDLE_CONFIGURED else "",
        # Same "not offered yet until configured" rule for the Max tier.
        "price_id_max": PADDLE_PRICE_ID_MAX if PADDLE_CONFIGURED else "",
        "price_id_max_annual": PADDLE_PRICE_ID_MAX_ANNUAL if PADDLE_CONFIGURED else "",
        "environment": PADDLE_ENV,
        "price_usd": PRO_PRICE_USD,
        "price_iqd": PRO_PRICE_IQD,
        # Always available for the local (ZainCash/QiCard) rails -- both are
        # one-time passes, so "annual" is just a longer one-time pass, no
        # extra setup needed the way Paddle's recurring billing requires.
        "price_usd_annual": PRO_PRICE_USD_ANNUAL,
        "price_iqd_annual": PRO_PRICE_IQD_ANNUAL,
        # Max tier -- everything Pro includes, plus AI Roleplay (coming soon).
        "price_usd_max": MAX_PRICE_USD,
        "price_iqd_max": MAX_PRICE_IQD,
        "price_usd_max_annual": MAX_PRICE_USD_ANNUAL,
        "price_iqd_max_annual": MAX_PRICE_IQD_ANNUAL,
        "customer_email": user.email,
        "user_id": user.id,
    }


def verify_paddle_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    """
    Paddle signs each webhook with your PADDLE_WEBHOOK_SECRET so you can
    prove a request genuinely came from Paddle and wasn't forged by someone
    trying to grant themselves free Pro access. This is THE security-critical
    function in the whole payments system — see billing_test.py for how
    thoroughly this is tested (valid signatures accepted, anything else
    rejected, including tampered bodies and reused/malformed headers).

    Paddle's format: header looks like "ts=1234567890;h1=<hex-hmac>".
    The signed message is "{ts}:{raw_body}", HMAC-SHA256'd with your secret.
    """
    if not signature_header or not secret:
        return False
    parts = dict(p.split("=", 1) for p in signature_header.split(";") if "=" in p)
    ts, h1 = parts.get("ts"), parts.get("h1")
    if not ts or not h1:
        return False
    signed_payload = f"{ts}:".encode() + raw_body
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, h1)


@app.post("/api/billing/webhook")
async def paddle_webhook(request: Request, session: Session = Depends(get_session)):
    """
    Paddle calls this after real payment events. This is the ONLY place in
    the whole app that may set is_premium=True from a payment — never the
    browser, never a plain API call. Every request here is verified against
    PADDLE_WEBHOOK_SECRET before anything in it is trusted.
    """
    if not PADDLE_CONFIGURED:
        raise HTTPException(503, "Payments are not configured on this server.")

    raw_body = await request.body()
    signature = request.headers.get("paddle-signature", "")
    if not verify_paddle_signature(raw_body, signature, PADDLE_WEBHOOK_SECRET):
        # Do not process anything from an unverified request. This is what
        # stops someone from POSTing a fake "payment succeeded" event.
        raise HTTPException(400, "Invalid webhook signature.")

    event = _json.loads(raw_body)
    event_type = event.get("event_type", "")
    data = event.get("data", {})
    custom_data = data.get("custom_data") or {}
    user_id = custom_data.get("user_id")

    user = None
    if user_id:
        user = session.get(User, int(user_id))
    if not user:
        customer_id = data.get("customer_id")
        if customer_id:
            user = session.exec(select(User).where(
                User.paddle_customer_id == customer_id)).first()
    if not user:
        # Nothing to act on — acknowledge so Paddle doesn't keep retrying,
        # but don't grant anyone anything.
        return {"received": True, "matched_user": False}

    if event_type in ("subscription.created", "subscription.activated",
                      "subscription.resumed", "transaction.completed"):
        user.is_premium = True
        user.subscription_status = "active"
        user.paddle_customer_id = data.get("customer_id") or user.paddle_customer_id
        user.paddle_subscription_id = data.get("id") or user.paddle_subscription_id
    elif event_type in ("subscription.canceled", "subscription.paused"):
        user.is_premium = False
        user.subscription_status = "canceled"
    elif event_type == "subscription.past_due":
        # Payment failed but hasn't been formally canceled yet — Paddle will
        # retry the charge. Keep access for now; revoke only on cancellation.
        user.subscription_status = "past_due"
    else:
        return {"received": True, "handled": False}

    session.add(user)
    session.commit()
    return {"received": True, "handled": True}


# ----------------------------------------------------------------------
# 6b. PAYMENTS — ZainCash
# ----------------------------------------------------------------------
_zaincash_token_cache = {"token": None, "expires_at": 0.0}


def get_zaincash_token() -> str:
    """
    Gets an OAuth2 access token from ZainCash (client_credentials grant),
    cached in memory so we don't re-authenticate on every checkout click.
    """
    now = time.time()
    if _zaincash_token_cache["token"] and now < _zaincash_token_cache["expires_at"]:
        return _zaincash_token_cache["token"]

    resp = requests.post(
        f"{ZAINCASH_BASE_URL}/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": ZAINCASH_CLIENT_ID,
            "client_secret": ZAINCASH_CLIENT_SECRET,
            "scope": "payment:read payment:write",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _zaincash_token_cache["token"] = data["access_token"]
    # Refresh a little early so we never hand out a token that expires
    # mid-request.
    _zaincash_token_cache["expires_at"] = now + max(data.get("expires_in", 300) - 30, 30)
    return _zaincash_token_cache["token"]


def zaincash_inquiry(transaction_id: str) -> str | None:
    """
    Calls ZainCash's Transaction Inquiry API — the authoritative source of
    truth for whether a payment actually went through (SUCCESS / FAILED /
    PENDING / etc). We rely on this rather than trusting the redirect alone,
    since only a real server-to-server call using our own credentials can't
    be forged by someone just visiting a URL.
    """
    try:
        token = get_zaincash_token()
        resp = requests.get(
            f"{ZAINCASH_BASE_URL}/api/v2/payment-gateway/transaction/inquiry/{transaction_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        # Confirmed by direct testing: the Inquiry response is a FLAT object
        # ({"status": "SUCCESS", ...}), unlike the init response which nests
        # under "data" — this used to always return None even on a real
        # SUCCESS. Handle both shapes just in case that ever changes.
        data = body.get("data", body)
        return data.get("status")
    except requests.RequestException:
        return None


class CheckoutPlanIn(BaseModel):
    plan: str = "monthly"
    tier: str = "pro"


@app.post("/api/billing/zaincash/checkout")
def zaincash_checkout(data: CheckoutPlanIn, request: Request,
                       user: User = Depends(get_current_user),
                       session: Session = Depends(get_session)):
    """
    Starts a ZainCash payment. Creates a transaction on ZainCash's side and
    returns the redirectUrl — the frontend sends the browser's full page
    there (not an overlay/iframe; ZainCash doesn't support embedding). The
    customer enters their wallet phone number + OTP on ZainCash's own page,
    so we never see or touch that.
    """
    if not ZAINCASH_CONFIGURED:
        raise HTTPException(503, "ZainCash is not configured on this server.")
    plan = data.plan if data.plan in PRO_PLAN_DAYS else "monthly"
    tier = data.tier if data.tier in ("pro", "max") else "pro"
    if tier == "max":
        amount_iqd = MAX_PRICE_IQD_ANNUAL if plan == "annual" else MAX_PRICE_IQD
    else:
        amount_iqd = PRO_PRICE_IQD_ANNUAL if plan == "annual" else PRO_PRICE_IQD
    # Remembered now, read back whenever this transaction is confirmed
    # (callback, or the /sync fallback) so the right number of days AND the
    # right tier get granted -- see PRO_PLAN_DAYS.
    user.checkout_plan = plan
    user.checkout_tier = tier
    session.add(user)
    session.commit()

    # order_id is OUR tracking id (embeds the user id, see _confirm_and_grant_zaincash).
    # externalReferenceId is a SEPARATE field ZainCash requires to be a UUID —
    # conflating the two caused a 400 Bad Request the first time this was tested.
    order_id = f"speakport-{user.id}-{int(time.time())}"
    base = str(request.base_url).rstrip("/")
    token = get_zaincash_token()

    resp = requests.post(
        f"{ZAINCASH_BASE_URL}/api/v2/payment-gateway/transaction/init",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "language": "en",
            "externalReferenceId": str(uuid.uuid4()),
            "orderId": order_id,
            "serviceType": ZAINCASH_SERVICE_TYPE,
            "amount": {"value": amount_iqd, "currency": "IQD"},
            "redirectUrls": {
                "successUrl": f"{base}/api/billing/zaincash/callback?order_id={order_id}",
                "failureUrl": f"{base}/?upgrade=failed",
            },
        },
        timeout=15,
    )
    if not resp.ok:
        # Surface ZainCash's actual error body instead of a bare 500 — this is
        # what made the first bad request hard to diagnose without digging
        # through Render's logs.
        raise HTTPException(502, f"ZainCash rejected the request ({resp.status_code}): {resp.text[:500]}")
    body = resp.json()
    data = body.get("data", body)  # some responses may not nest under "data"

    redirect_url = (data.get("redirectUrl") or data.get("url") or data.get("checkoutUrl")
                     or data.get("redirect_url") or data.get("paymentUrl") or data.get("link"))
    if not redirect_url:
        # None of the known field names matched — surface the exact response
        # so this is fixable from the error message alone, not a guessing game.
        raise HTTPException(502, f"ZainCash didn't return a redirect URL. Raw response: {_json.dumps(body)[:800]}")

    # Save ZainCash's OWN transaction id so the callback (and the /sync
    # fallback below) can confirm the real status via the Inquiry API.
    # Their init response doesn't reliably expose it under "transactionId"
    # (confirmed by testing: it caused the Inquiry API to reject our order_id
    # with "Failed to convert 'referenceId'"), but the redirect URL always
    # carries it as ?id=<uuid> — that's the one place we can trust.
    parsed_id = parse_qs(urlparse(redirect_url).query).get("id", [None])[0]
    user.zaincash_transaction_id = (
        parsed_id or data.get("transactionId") or data.get("id")
        or data.get("transaction_id") or order_id
    )
    session.add(user)
    session.commit()

    return {"redirect_url": redirect_url}


def _confirm_and_grant_zaincash(order_id: str, session: Session) -> bool:
    """
    Looks up the user embedded in our own order_id (we control this format:
    "speakport-{user_id}-{timestamp}"), then asks ZainCash's Inquiry API
    whether that transaction actually succeeded before granting anything.
    """
    try:
        user_id = int(order_id.split("-")[1])
    except (IndexError, ValueError):
        return False
    user = session.get(User, user_id)
    if not user or not user.zaincash_transaction_id:
        return False
    if zaincash_inquiry(user.zaincash_transaction_id) != "SUCCESS":
        return False
    user.is_premium = True
    user.subscription_status = "active"
    user.plan_tier = user.checkout_tier
    user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=PRO_PLAN_DAYS.get(user.checkout_plan, 30))
    session.add(user)
    session.commit()
    return True


@app.get("/api/billing/zaincash/callback")
def zaincash_callback(order_id: str = "", session: Session = Depends(get_session)):
    """
    ZainCash redirects the customer's browser here after they finish paying.
    Pro is only ever granted after confirming the transaction with ZainCash
    itself via the Inquiry API — never from the redirect alone, which
    someone could otherwise forge just by visiting this URL.
    """
    granted = _confirm_and_grant_zaincash(order_id, session) if order_id else False
    return RedirectResponse(url="/?paid=1" if granted else "/?upgrade=pending")


@app.post("/api/billing/zaincash/sync")
def zaincash_sync(user: User = Depends(get_current_user),
                   session: Session = Depends(get_session)):
    """
    Safety net for when the redirect back from ZainCash doesn't fire (closed
    tab, flaky connection, etc). The frontend calls this after returning
    from checkout to re-check the user's own last transaction.
    """
    if user.zaincash_transaction_id and not user.is_premium:
        if zaincash_inquiry(user.zaincash_transaction_id) == "SUCCESS":
            user.is_premium = True
            user.subscription_status = "active"
            user.plan_tier = user.checkout_tier
            user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=PRO_PLAN_DAYS.get(user.checkout_plan, 30))
            session.add(user)
            session.commit()
    return {"is_premium": user.is_premium}


# Note: ZainCash also supports webhooks for async status updates, but their
# exact payload shape needs a real merchant account to see and test — see
# https://docs.zaincash.iq/ once you have live credentials. Their docs
# explicitly say the webhook is optional and the redirect above is enough
# to go live; add a /api/billing/zaincash/webhook handler later if you want
# faster confirmation for customers who don't get redirected back.


# ----------------------------------------------------------------------
# 6c. PAYMENTS — QiCard ("Pay with SuperQi")
# ----------------------------------------------------------------------
# A second, separate Iraqi payment rail alongside ZainCash. QiCard's REST
# API mirrors the same shape: create a payment, redirect the browser to a
# hosted formUrl, then confirm server-to-server before granting anything —
# same security posture as zaincash_inquiry() above.
def qicard_get_status(payment_id: str) -> str | None:
    """
    Calls QiCard's payment endpoint to get the authoritative status
    (SUCCESS / FAILED / CREATED / AUTHENTICATION_FAILED) — never trust a
    client-side redirect or webhook body alone; always re-check here first.
    Returns None if the call itself failed (network error, bad credentials).
    """
    try:
        resp = requests.get(
            f"{QICARD_BASE_URL}/api/v1/payment/{payment_id}",
            headers={"X-Terminal-Id": QICARD_TERMINAL_ID},
            auth=(QICARD_USERNAME, QICARD_PASSWORD),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("status")
    except requests.RequestException:
        return None


@app.post("/api/billing/qicard/checkout")
def qicard_checkout(data: CheckoutPlanIn, request: Request,
                     user: User = Depends(get_current_user),
                     session: Session = Depends(get_session)):
    """
    Starts a QiCard payment. Creates a Payment on QiCard's side and returns
    their hosted formUrl — the frontend sends the whole browser page there
    (no overlay/iframe support, same as ZainCash). QiCard's own checkout
    page offers both card entry AND "Pay with SuperQi" (QR/wallet), so we
    never have to choose between them ourselves.
    """
    if not QICARD_CONFIGURED:
        raise HTTPException(503, "QiCard is not configured on this server.")
    plan = data.plan if data.plan in PRO_PLAN_DAYS else "monthly"
    tier = data.tier if data.tier in ("pro", "max") else "pro"
    if tier == "max":
        amount_iqd = MAX_PRICE_IQD_ANNUAL if plan == "annual" else MAX_PRICE_IQD
    else:
        amount_iqd = PRO_PRICE_IQD_ANNUAL if plan == "annual" else PRO_PRICE_IQD
    user.checkout_plan = plan
    user.checkout_tier = tier
    session.add(user)
    session.commit()

    base = str(request.base_url).rstrip("/")
    resp = requests.post(
        f"{QICARD_BASE_URL}/api/v1/payment",
        headers={"X-Terminal-Id": QICARD_TERMINAL_ID, "Content-Type": "application/json"},
        auth=(QICARD_USERNAME, QICARD_PASSWORD),
        json={
            "requestId": str(uuid.uuid4()),
            "amount": float(amount_iqd),
            "currency": "IQD",
            "locale": "en_US",
            # Embedding the user id directly here (rather than parsing it back
            # out of an order-id string like the ZainCash integration has to)
            # since QiCard's finishPaymentUrl is just a plain query string.
            "finishPaymentUrl": f"{base}/api/billing/qicard/callback?user_id={user.id}",
            "notificationUrl": f"{base}/api/billing/qicard/webhook",
            "customerInfo": {"email": user.email, "accountId": str(user.id)},
            "appChannel": False,   # this is a web checkout, not a mobile app
        },
        timeout=15,
    )
    if not resp.ok:
        raise HTTPException(502, f"QiCard rejected the request ({resp.status_code}): {resp.text[:500]}")
    body = resp.json()
    payment_id = body.get("paymentId")
    redirect_url = body.get("formUrl")
    if not payment_id or not redirect_url:
        raise HTTPException(502, f"QiCard didn't return a payment id/formUrl. Raw response: {_json.dumps(body)[:800]}")

    user.qicard_payment_id = payment_id
    session.add(user)
    session.commit()
    return {"redirect_url": redirect_url}


def _confirm_and_grant_qicard(user_id: int, session: Session) -> bool:
    """Looks up the user by id and grants Pro only if QiCard confirms SUCCESS."""
    user = session.get(User, user_id)
    if not user or not user.qicard_payment_id:
        return False
    if qicard_get_status(user.qicard_payment_id) != "SUCCESS":
        return False
    user.is_premium = True
    user.subscription_status = "active"
    user.plan_tier = user.checkout_tier
    user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=PRO_PLAN_DAYS.get(user.checkout_plan, 30))
    session.add(user)
    session.commit()
    return True


@app.get("/api/billing/qicard/callback")
def qicard_callback(user_id: int = 0, session: Session = Depends(get_session)):
    """
    QiCard redirects the customer's browser here (finishPaymentUrl) once
    they finish paying. Pro is only ever granted after independently
    confirming the payment via qicard_get_status() — never from the
    redirect alone, which anyone could otherwise forge just by visiting
    this URL with a guessed user_id.
    """
    granted = _confirm_and_grant_qicard(user_id, session) if user_id else False
    return RedirectResponse(url="/?paid=1" if granted else "/?upgrade=pending")


@app.post("/api/billing/qicard/webhook")
async def qicard_webhook(request: Request, session: Session = Depends(get_session)):
    """
    QiCard's notificationUrl webhook — fired server-to-server when a
    payment's status changes. We couldn't confirm QiCard's exact webhook
    signature-verification scheme (their docs page for it wasn't reachable
    while building this), so rather than trust the webhook BODY at all, we
    treat it purely as a low-latency trigger: pull out the paymentId it
    mentions and independently re-verify status via our own authenticated
    API call before granting anything. This is safe even with zero trust
    in the payload's contents — same principle as the /sync fallback below.
    """
    try:
        body = await request.json()
    except Exception:
        return {"received": True, "matched_user": False}
    payment_id = body.get("paymentId") or body.get("payment_id")
    if not payment_id:
        return {"received": True, "matched_user": False}
    user = session.exec(select(User).where(User.qicard_payment_id == payment_id)).first()
    if not user:
        return {"received": True, "matched_user": False}
    if not user.is_premium and qicard_get_status(payment_id) == "SUCCESS":
        user.is_premium = True
        user.subscription_status = "active"
        user.plan_tier = user.checkout_tier
        user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=PRO_PLAN_DAYS.get(user.checkout_plan, 30))
        session.add(user)
        session.commit()
    return {"received": True}


@app.post("/api/billing/qicard/sync")
def qicard_sync(user: User = Depends(get_current_user),
                 session: Session = Depends(get_session)):
    """
    Safety net for when the redirect back from QiCard doesn't fire (closed
    tab, flaky connection, etc). The frontend calls this after returning
    from checkout to re-check the user's own last payment.
    """
    if user.qicard_payment_id and not user.is_premium:
        if qicard_get_status(user.qicard_payment_id) == "SUCCESS":
            user.is_premium = True
            user.subscription_status = "active"
            user.plan_tier = user.checkout_tier
            user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=PRO_PLAN_DAYS.get(user.checkout_plan, 30))
            session.add(user)
            session.commit()
    return {"is_premium": user.is_premium}


# ----------------------------------------------------------------------
# 7b. SPRINT ROUTES — the intensive course
# ----------------------------------------------------------------------
def _get_sprint_or_404(sprint_id: str) -> dict:
    sprint_def = SPRINTS.get(sprint_id)
    if not sprint_def:
        raise HTTPException(404, "That Sprint doesn't exist.")
    return sprint_def


def _sprint_gated(user: User, sprint_def: dict, session: Session) -> bool:
    """True if this Sprint has a prerequisite (unlock_after) that isn't
    finished yet -- e.g. the Business Sprint stays gated until the Core
    Sprint is done, so there's something new to unlock after "finishing
    everything," instead of dumping all content on day one.

    Admins always bypass this. The gate is a retention mechanic for real
    subscribers; it should never block an admin's own testing. This matters
    in practice: /api/admin/sprint/unlock-all deliberately does NOT
    fake-complete a Sprint's days (you still practice each one for real --
    see its docstring), so an admin who just unlocked the calendar hasn't
    actually "finished" the prerequisite yet, and would otherwise stay
    gated out of the very thing they're trying to test.
    """
    if user.is_admin:
        return False
    unlock_after = sprint_def.get("unlock_after")
    if not unlock_after:
        return False
    return not _sprint_state(user, unlock_after, session).get("finished")


def _sprint_state(user: User, sprint_id: str, session: Session) -> dict:
    """Works out where the user is in the given Sprint right now."""
    sprint_def = SPRINTS[sprint_id]
    total_days = len(sprint_def["days"])

    enr = session.exec(
        select(Enrollment).where(Enrollment.user_id == user.id,
                                 Enrollment.sprint_id == sprint_id)
    ).first()
    if not enr:
        return {"enrolled": False, "total_days": total_days}

    drill_rows = session.exec(
        select(DayCompletion).where(DayCompletion.user_id == user.id,
                                    DayCompletion.sprint_id == sprint_id)
    ).all()
    drill_done = {r.day_number: r.avg_score for r in drill_rows}

    conv_rows = session.exec(
        select(DayConvDone).where(DayConvDone.user_id == user.id,
                                  DayConvDone.sprint_id == sprint_id)
    ).all()
    conv_done = {r.day_number for r in conv_rows}

    # A day is only truly CLEARED once both stages are done: the quick
    # drill, then a real conversation that puts those phrases to use.
    done = {d: score for d, score in drill_done.items() if d in conv_done}

    # How many days have passed since enrolling. Day 1 unlocks immediately.
    elapsed = (dt.datetime.utcnow() - enr.started_at).days
    unlocked_through = min(elapsed + 1, total_days)

    # Streak = consecutive completed days counting back from the newest one.
    streak = 0
    if done:
        latest = max(done)
        n = latest
        while n in done:
            streak += 1
            n -= 1

    scores = list(done.values())
    return {
        "enrolled": True,
        "started_at": enr.started_at.isoformat(),
        "unlocked_through": unlocked_through,
        "completed_days": sorted(done),
        "drill_done_days": sorted(drill_done),
        "conv_done_days": sorted(conv_done),
        "scores_by_day": {str(k): v for k, v in done.items()},
        "streak": streak,
        "total_days": total_days,
        "percent": round(len(done) / total_days * 100),
        "avg_score": round(sum(scores) / len(scores)) if scores else 0,
        "finished": len(done) == total_days,
        "pass_score": PASS_SCORE,
    }


@app.get("/api/sprint")
def get_sprint(sprint_id: str = DEFAULT_SPRINT_ID, user: User = Depends(get_current_user),
               session: Session = Depends(get_session)):
    """Sprint overview. Day content is only sent for days that are unlocked."""
    sprint_def = _get_sprint_or_404(sprint_id)
    state = _sprint_state(user, sprint_id, session)
    unlocked_through = state.get("unlocked_through", 0) if state["enrolled"] else 0
    drill_set = set(state.get("drill_done_days", []))
    conv_set = set(state.get("conv_done_days", []))
    convs = SPRINT_CONVS_BY_SPRINT[sprint_id]

    days = []
    for d in sprint_def["days"]:
        # A day is open if: enrolled, premium, and its turn has arrived.
        open_now = (state["enrolled"] and user.is_premium
                    and d["day"] <= unlocked_through)
        day_conv = convs.get(d["day"])
        days.append({
            "day": d["day"],
            "theme": d["theme"],
            "locked": not open_now,
            # Content stays on the server until the day is genuinely unlocked.
            "challenge": d["challenge"] if open_now else "",
            "phrases": d["phrases"] if open_now else [],
            # Just enough for the day card; the full dialogue comes from
            # /api/conversation/sprintday-{sprint_id}-{n} when opened.
            "conv": ({"setting": day_conv["setting"], "goal": day_conv["goal"]}
                     if open_now and day_conv else None),
            "drill_done": d["day"] in drill_set,
            "conv_done": d["day"] in conv_set,
        })

    return {
        "id": sprint_def["id"],
        "title": sprint_def["title"],
        "promise": sprint_def["promise"],
        "is_premium_user": user.is_premium,
        "gated": _sprint_gated(user, sprint_def, session),
        "days": days,
        "state": state,
    }


class EnrollIn(BaseModel):
    sprint_id: str = DEFAULT_SPRINT_ID


@app.post("/api/sprint/enroll")
def enroll(data: EnrollIn = EnrollIn(), user: User = Depends(get_current_user),
           session: Session = Depends(get_session)):
    if not user.is_premium:
        raise HTTPException(403, "The Sprint is a Pro program.")
    sprint_def = _get_sprint_or_404(data.sprint_id)
    if _sprint_gated(user, sprint_def, session):
        raise HTTPException(403, "Finish the Core Sprint first to unlock this one.")
    existing = session.exec(
        select(Enrollment).where(Enrollment.user_id == user.id,
                                 Enrollment.sprint_id == data.sprint_id)
    ).first()
    if existing:
        raise HTTPException(400, "You're already enrolled in this Sprint.")
    session.add(Enrollment(user_id=user.id, sprint_id=data.sprint_id))
    session.commit()
    return _sprint_state(user, data.sprint_id, session)


class DayDoneIn(BaseModel):
    day: int
    avg_score: int
    sprint_id: str = DEFAULT_SPRINT_ID


@app.post("/api/sprint/day/complete")
def complete_day(data: DayDoneIn, user: User = Depends(get_current_user),
                 session: Session = Depends(get_session)):
    """
    Marks the DRILL stage of a day as passed (the 5 phrase repeats).
    This is stage 1 of 2 — the day only fully clears once the
    conversation stage (below) is also done. Kept as /day/complete
    for backward compatibility with existing clients.
    """
    if not user.is_premium:
        raise HTTPException(403, "The Sprint is a Pro program.")
    _get_sprint_or_404(data.sprint_id)
    state = _sprint_state(user, data.sprint_id, session)
    if not state["enrolled"]:
        raise HTTPException(400, "Start the Sprint first.")
    if data.day not in SPRINT_DAY_BY_NUM_BY_SPRINT[data.sprint_id]:
        raise HTTPException(404, "That day doesn't exist.")
    # The core rule: you cannot jump ahead of the calendar.
    if data.day > state["unlocked_through"]:
        raise HTTPException(403, "That day hasn't unlocked yet. Come back tomorrow.")

    score = max(0, min(100, int(data.avg_score)))
    if score < PASS_SCORE:
        raise HTTPException(400, f"You need {PASS_SCORE}% or higher to finish the day.")

    existing = session.exec(
        select(DayCompletion).where(DayCompletion.user_id == user.id,
                                    DayCompletion.sprint_id == data.sprint_id,
                                    DayCompletion.day_number == data.day)
    ).first()
    if existing:
        # Already done — keep the best score.
        existing.avg_score = max(existing.avg_score, score)
        session.add(existing)
    else:
        session.add(DayCompletion(user_id=user.id, sprint_id=data.sprint_id,
                                  day_number=data.day, avg_score=score))
    session.commit()
    return _sprint_state(user, data.sprint_id, session)


class DayNumIn(BaseModel):
    day: int
    sprint_id: str = DEFAULT_SPRINT_ID


@app.post("/api/sprint/day/conv-complete")
def complete_day_conv(data: DayNumIn, user: User = Depends(get_current_user),
                      session: Session = Depends(get_session)):
    """
    Marks stage 2 (the CLT conversation) as done for a Sprint day.
    Requires the drill stage to already be passed — you talk about
    the phrases you just practiced, not before.
    """
    if not user.is_premium:
        raise HTTPException(403, "The Sprint is a Pro program.")
    _get_sprint_or_404(data.sprint_id)
    state = _sprint_state(user, data.sprint_id, session)
    if not state["enrolled"]:
        raise HTTPException(400, "Start the Sprint first.")
    if data.day not in SPRINT_DAY_BY_NUM_BY_SPRINT[data.sprint_id]:
        raise HTTPException(404, "That day doesn't exist.")
    if data.day not in state.get("drill_done_days", []):
        raise HTTPException(400, "Finish today's phrase drill first.")

    existing = session.exec(
        select(DayConvDone).where(DayConvDone.user_id == user.id,
                                  DayConvDone.sprint_id == data.sprint_id,
                                  DayConvDone.day_number == data.day)
    ).first()
    if not existing:
        session.add(DayConvDone(user_id=user.id, sprint_id=data.sprint_id, day_number=data.day))
        session.commit()
    return _sprint_state(user, data.sprint_id, session)


@app.get("/api/sprint/certificate")
def certificate(sprint_id: str = DEFAULT_SPRINT_ID, user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    sprint_def = _get_sprint_or_404(sprint_id)
    state = _sprint_state(user, sprint_id, session)
    if not state.get("finished"):
        raise HTTPException(403, "Finish all the days to earn your certificate.")
    return {
        "name": user.email.split("@")[0],
        "title": sprint_def["title"],
        "avg_score": state["avg_score"],
        "issued_on": dt.date.today().isoformat(),
    }


# ----------------------------------------------------------------------
# 7d. CONTENT ENGINE — serves practice + conversations from content.py
# ----------------------------------------------------------------------
# No API. No keys. No rate limits. Everything below reads from the built-in
# content bank, so it works identically for one user or a million.
import random


def _tr_for(lang: str, ar_text: str) -> str:
    """We only ship Arabic translations for now; fall back to '' otherwise."""
    return ar_text if lang == "ar" else ""


# ---- Practice sentences (timed drilling) ----
class SentencesIn(BaseModel):
    topic: str = ""
    level: str = "Beginner"
    count: int = 20
    avoid: list[str] = []   # sentences already shown this session


@app.post("/api/sentences")
def sentences(data: SentencesIn, user: User = Depends(get_current_user)):
    """
    Returns a batch of practice sentences from the bank, shuffled, skipping
    ones already seen this session. Each comes with its Arabic translation.

    This powers the TIMED drilling sessions (Sprint days + "Drill any topic"),
    which are a Pro feature. Free users still get the fixed warm-up lessons and
    the free conversations — this endpoint is the paid, unlimited-practice part.
    """
    if not user.is_premium:
        raise HTTPException(403, "Timed practice sessions are a Pro feature.")
    level = data.level if data.level in SENTENCE_BANK else "Beginner"
    count = max(5, min(30, int(data.count)))
    avoid = set(s.strip() for s in data.avoid)

    pool = SENTENCE_BANK[level][:]
    random.shuffle(pool)
    fresh = [s for s in pool if s["en"] not in avoid]
    # If they've exhausted the level this session, allow repeats (reshuffled).
    chosen = (fresh or pool)[:count]
    return {"level": level, "topic": data.topic,
            "sentences": [s["en"] for s in chosen],
            "translations": {s["en"]: s["ar"] for s in chosen}}


# ---- Translation (served from the bank, instant) ----
class TranslateIn(BaseModel):
    text: str
    lang: str = "ar"


# LESSONS (above) stores phrases as plain English strings, unlike
# SENTENCE_BANK/CONVERSATIONS/SPRINT_CONVS which already carry "en"/"ar"
# pairs. Without this, the "Translate" button on every Practice Lessons
# phrase silently returned an empty string — found while testing the app.
LESSON_TRANSLATIONS = {
    'Hello, nice to meet you.': 'مرحباً، سعيد بلقائك.',
    'Hi there, how are you doing today?': 'مرحباً، كيف حالك اليوم؟',
    "Good morning! It's nice to meet you.": 'صباح الخير! سعيد بلقائك.',
    "Good afternoon, I don't think we've met yet.": 'مساء الخير، لا أعتقد أننا التقينا من قبل.',
    "Hi, I'm glad we finally get to talk.": 'مرحباً، يسعدني أننا تحدثنا أخيراً.',
    "Hello, I've heard a lot about you.": 'مرحباً، سمعت الكثير عنك.',
    'Nice to finally put a face to the name.': 'سررت أخيراً برؤية وجهك بعد سماع اسمك.',
    "Hi, I don't believe we've been introduced.": 'مرحباً، أعتقد أننا لم نتعارف بعد.',
    "Good evening, it's a pleasure to meet you.": 'مساء الخير، يسعدني لقاؤك.',
    'Hello, welcome! Make yourself at home.': 'مرحباً، أهلاً بك! اعتبر نفسك في بيتك.',
    "My name is Sara. What's your name?": 'اسمي سارة. ما اسمك؟',
    "Sorry, I didn't catch your name.": 'آسف، لم أفهم اسمك جيداً.',
    'Can you tell me your name again?': 'هل يمكنك أن تخبرني باسمك مرة أخرى؟',
    'What should I call you?': 'ماذا يجب أن أناديك؟',
    'Is it okay if I call you by your first name?': 'هل يمكنني مناداتك باسمك الأول؟',
    'How do you spell your last name?': 'كيف تكتب اسم عائلتك؟',
    'My friends call me Sam, by the way.': 'أصدقائي ينادونني سام، بالمناسبة.',
    'I go by my middle name, actually.': 'أنا في الواقع أستخدم اسمي الأوسط.',
    "What's your full name, if you don't mind me asking?": 'ما اسمك الكامل، إذا كنت لا تمانع سؤالي؟',
    'Nice name — where does it come from?': 'اسم جميل — من أين أصله؟',
    'Where are you from?': 'من أين أنت؟',
    'Which city do you live in?': 'في أي مدينة تعيش؟',
    'Have you always lived here?': 'هل عشت هنا دائماً؟',
    "I'm originally from Basra, but I moved here recently.": 'أنا أصلاً من البصرة، لكنني انتقلت إلى هنا مؤخراً.',
    'What part of the country are you from?': 'من أي جزء من البلاد أنت؟',
    'Do you go back home often?': 'هل تعود إلى بلدك كثيراً؟',
    'How long have you lived in this city?': 'منذ متى وأنت تعيش في هذه المدينة؟',
    'Is this your hometown?': 'هل هذه مدينتك الأصلية؟',
    "I've never been to your country — what's it like?": 'لم أزر بلدك من قبل — كيف هو؟',
    'What brought you to this city?': 'ما الذي جلبك إلى هذه المدينة؟',
    "I'm learning English to travel.": 'أتعلم الإنجليزية من أجل السفر.',
    'I work in marketing, and you?': 'أعمل في التسويق، وأنت؟',
    "I'm a student at the local university.": 'أنا طالب في الجامعة المحلية.',
    'I moved here a few months ago for work.': 'انتقلت إلى هنا قبل بضعة أشهر من أجل العمل.',
    "I've been studying English for about a year.": 'أدرس الإنجليزية منذ حوالي سنة.',
    "I'm here on a short business trip.": 'أنا هنا في رحلة عمل قصيرة.',
    "I'm still new to this city, actually.": 'أنا في الواقع ما زلت جديداً في هذه المدينة.',
    'I spend most of my free time reading.': 'أقضي معظم وقت فراغي في القراءة.',
    'I have two younger siblings back home.': 'لدي شقيقان أصغر مني في بلدي.',
    'I recently changed careers.': 'غيّرت مهنتي مؤخراً.',
    'How are you doing today?': 'كيف حالك اليوم؟',
    "How's everything going?": 'كيف تسير الأمور؟',
    'How have you been lately?': 'كيف كنت مؤخراً؟',
    'Is everything okay with you?': 'هل كل شيء بخير معك؟',
    'You seem happy today — good news?': 'تبدو سعيداً اليوم — أخبار جيدة؟',
    'How was your weekend?': 'كيف كانت عطلة نهاية الأسبوع؟',
    "How's your family doing?": 'كيف حال عائلتك؟',
    "How's work been treating you?": 'كيف يعاملك العمل؟',
    'Everything going well on your end?': 'هل كل شيء على ما يرام من جانبك؟',
    "It's been a while — how have things been?": 'مضى وقت طويل — كيف كانت الأمور؟',
    'This is my colleague, Ahmed.': 'هذا زميلي، أحمد.',
    'Have you two met before?': 'هل التقيتما من قبل؟',
    'Let me introduce you to my friend.': 'دعني أعرّفك على صديقي.',
    "I'd like you to meet my manager.": 'أود أن تقابل مديري.',
    'This is Layla, she just joined our team.': 'هذه ليلى، لقد انضمت للتو إلى فريقنا.',
    'Allow me to introduce my wife.': 'اسمح لي أن أعرّفك على زوجتي.',
    'Meet my neighbor, he just moved in.': 'تعرّف على جاري، لقد انتقل للتو إلى هنا.',
    "I don't think you've met my brother yet.": 'لا أعتقد أنك قابلت أخي بعد.',
    "This is someone I'd love for you to know.": 'هذا شخص أود منك أن تتعرف عليه.',
    'Let me introduce the two of you properly.': 'دعني أعرّفكما ببعض بشكل صحيح.',
    "Lovely weather we're having today, isn't it?": 'الطقس جميل اليوم، أليس كذلك؟',
    "It's quite hot outside today.": 'الجو حار جداً في الخارج اليوم.',
    'I heard it might rain later.': 'سمعت أنه قد تمطر لاحقاً.',
    'This has been a busy week for me.': 'كان هذا أسبوعاً مزدحماً بالنسبة لي.',
    "It's finally starting to feel like spring.": 'أخيراً بدأ الجو يشبه الربيع.',
    "I can't believe how cold it got last night.": 'لا أصدق كم أصبح الجو بارداً الليلة الماضية.',
    'Is it always this humid here in summer?': 'هل الجو رطب دائماً هكذا هنا في الصيف؟',
    'What a beautiful morning!': 'يا له من صباح جميل!',
    'I hope the weather stays nice for the weekend.': 'أتمنى أن يبقى الطقس جميلاً لعطلة نهاية الأسبوع.',
    'It looks like a storm is coming.': 'يبدو أن عاصفة قادمة.',
    'It was great talking to you.': 'كان من الرائع التحدث معك.',
    'I should get going, but it was nice meeting you.': 'يجب أن أذهب الآن، لكن سررت بلقائك.',
    "Let's catch up again soon.": 'لنتواصل مرة أخرى قريباً.',
    'Take care, and see you around.': 'اعتنِ بنفسك، أراك لاحقاً.',
    "I'll see you next time, then.": 'سأراك في المرة القادمة إذاً.',
    'Have a safe trip home.': 'أتمنى لك رحلة آمنة إلى المنزل.',
    'It was a pleasure meeting you today.': 'كان من دواعي سروري مقابلتك اليوم.',
    'I hope we can talk again soon.': 'أتمنى أن نتحدث مرة أخرى قريباً.',
    'Goodbye for now, take care of yourself.': 'وداعاً الآن، اعتنِ بنفسك.',
    'Thanks for the chat — see you later.': 'شكراً على الحديث — أراك لاحقاً.',
    "Hi, I'm the new intern in the marketing team.": 'مرحباً، أنا المتدرب الجديد في فريق التسويق.',
    'I just started here last week.': 'بدأت العمل هنا للتو الأسبوع الماضي.',
    'Which department do you work in?': 'في أي قسم تعمل؟',
    "I've heard great things about your team.": 'سمعت أشياء رائعة عن فريقك.',
    'Are you also new here?': 'هل أنت جديد هنا أيضاً؟',
    'I look forward to working with you.': 'أتطلع للعمل معك.',
    'Who should I talk to about the project timeline?': 'مع من يجب أن أتحدث بخصوص الجدول الزمني للمشروع؟',
    "I'm still learning where everything is around the office.": 'ما زلت أتعلم أماكن الأشياء في المكتب.',
    'Let me know if you need any help settling in.': 'أخبرني إذا احتجت أي مساعدة للاستقرار.',
    'I sit just down the hall, feel free to stop by.': 'أجلس في نهاية الممر، لا تتردد في المرور.',
    "It's been a long time since we last spoke.": 'مضى وقت طويل منذ آخر مرة تحدثنا فيها.',
    "Wow, I didn't expect to run into you here!": 'واو، لم أتوقع أن أقابلك هنا!',
    'How funny running into you like this.': 'من الطريف أن أقابلك هكذا.',
    "It's so good to see a familiar face.": 'من الجميل جداً رؤية وجه مألوف.',
    'We should really catch up properly sometime.': 'يجب أن نتواصل بشكل جيد في وقت ما.',
    'I still remember the last time we met.': 'ما زلت أتذكر آخر مرة التقينا فيها.',
    "You haven't changed a bit!": 'لم تتغير أبداً!',
    "Small world, isn't it?": 'العالم صغير، أليس كذلك؟',
    "Let's exchange numbers so we don't lose touch again.": 'لنتبادل الأرقام حتى لا نفقد التواصل مرة أخرى.',
    "I'm really glad our paths crossed again.": 'يسعدني حقاً أن طريقينا التقيا مرة أخرى.',

    'Could I have a coffee, please?': 'هل يمكنني الحصول على قهوة، من فضلك؟',
    "I'll have a cappuccino, please.": 'سآخذ كابتشينو، من فضلك.',
    'Can I get a large iced latte?': 'هل يمكنني الحصول على لاتيه مثلج كبير؟',
    "I'd like a hot chocolate, please.": 'أريد شوكولاتة ساخنة، من فضلك.',
    'One black coffee, please, no sugar.': 'قهوة سوداء واحدة، من فضلك، بدون سكر.',
    'Could I get an espresso shot?': 'هل يمكنني الحصول على جرعة إسبريسو؟',
    "I'll take a medium tea, please.": 'سآخذ شاياً بحجم متوسط، من فضلك.',
    'Can I have a decaf coffee?': 'هل يمكنني الحصول على قهوة منزوعة الكافيين؟',
    "I'd like an iced tea, please.": 'أريد شاياً مثلجاً، من فضلك.',
    'Could you make that a double espresso?': 'هل يمكن أن تجعلها إسبريسو مزدوج؟',
    'What do you have on the menu today?': 'ماذا لديكم في القائمة اليوم؟',
    "What's your most popular drink?": 'ما هو أكثر مشروب طلباً لديكم؟',
    'Do you have any specials today?': 'هل لديكم أي عروض خاصة اليوم؟',
    'What kind of teas do you offer?': 'ما أنواع الشاي التي تقدمونها؟',
    'Could I see the menu, please?': 'هل يمكنني رؤية القائمة، من فضلك؟',
    "What's in this drink exactly?": 'ما مكونات هذا المشروب بالضبط؟',
    'Do you serve any seasonal drinks?': 'هل تقدمون مشروبات موسمية؟',
    'Is this drink served hot or cold?': 'هل يقدم هذا المشروب ساخناً أم بارداً؟',
    "What would you recommend for someone who doesn't like it too sweet?": 'بماذا تنصح لشخص لا يحب الحلاوة الزائدة؟',
    'Do you have a menu in English?': 'هل لديكم قائمة باللغة الإنجليزية؟',
    'How much is this sandwich?': 'كم سعر هذا الساندويتش؟',
    'Can I pay by card?': 'هل يمكنني الدفع بالبطاقة؟',
    'Do you accept cash?': 'هل تقبلون الدفع النقدي؟',
    'Is service included in the price?': 'هل الخدمة مشمولة في السعر؟',
    'Could I get a receipt, please?': 'هل يمكنني الحصول على إيصال، من فضلك؟',
    'How much do I owe you?': 'كم أدين لك؟',
    'Is there a discount for students?': 'هل هناك خصم للطلاب؟',
    'Can I split the bill with my friend?': 'هل يمكنني تقسيم الفاتورة مع صديقي؟',
    'Do you take contactless payment?': 'هل تقبلون الدفع بدون تلامس؟',
    'Is there an extra charge for oat milk?': 'هل هناك رسوم إضافية لحليب الشوفان؟',
    'Could you add a little extra sugar?': 'هل يمكن أن تضيف القليل من السكر الإضافي؟',
    'Can I get that with oat milk instead?': 'هل يمكنني الحصول عليه بحليب الشوفان بدلاً من ذلك؟',
    'No sugar for me, please.': 'بدون سكر لي، من فضلك.',
    'Could you make it extra hot?': 'هل يمكن أن تجعله ساخناً جداً؟',
    'Can I get an extra shot of espresso?': 'هل يمكنني الحصول على جرعة إسبريسو إضافية؟',
    "I'd like less ice in my drink, please.": 'أريد كمية أقل من الثلج في مشروبي، من فضلك.',
    'Could you leave out the whipped cream?': 'هل يمكن أن تستغني عن الكريمة المخفوقة؟',
    'Can you make it a bit sweeter?': 'هل يمكن أن تجعله أكثر حلاوة قليلاً؟',
    "I'll take that with skimmed milk, please.": 'سآخذه بالحليب القليل الدسم، من فضلك.',
    'Could I get it to go, extra strong?': 'هل يمكنني الحصول عليه للطريق، قوياً جداً؟',
    'Could I also get a croissant?': 'هل يمكنني الحصول على كرواسون أيضاً؟',
    'Do you have any fresh pastries today?': 'هل لديكم معجنات طازجة اليوم؟',
    "I'll take a slice of that cake, please.": 'سآخذ قطعة من تلك الكعكة، من فضلك.',
    'Is this muffin freshly baked?': 'هل هذا المافن مخبوز طازجاً؟',
    'Could I get a sandwich to go with my coffee?': 'هل يمكنني الحصول على ساندويتش مع قهوتي؟',
    'What pastries pair well with black coffee?': 'ما المعجنات التي تتناسب مع القهوة السوداء؟',
    'Can I get that warmed up, please?': 'هل يمكن تسخين ذلك، من فضلك؟',
    'Do you have any gluten-free options?': 'هل لديكم خيارات خالية من الغلوتين؟',
    "I'll have a cookie with my order, please.": 'سآخذ قطعة بسكويت مع طلبي، من فضلك.',
    'Could you recommend something sweet?': 'هل يمكن أن تنصح بشيء حلو؟',
    'Do you have any tea without sugar?': 'هل لديكم شاي بدون سكر؟',
    'Is this milk lactose-free?': 'هل هذا الحليب خالٍ من اللاكتوز؟',
    'Do you have a dairy-free option?': 'هل لديكم خيار خالٍ من منتجات الألبان؟',
    'Is there any sugar-free syrup available?': 'هل يتوفر شراب خالٍ من السكر؟',
    'Could you make this without caffeine?': 'هل يمكن أن تصنع هذا بدون كافيين؟',
    'Do you have any vegan pastries?': 'هل لديكم معجنات نباتية بالكامل؟',
    'Is this drink suitable for someone with a nut allergy?': 'هل هذا المشروب مناسب لشخص لديه حساسية من المكسرات؟',
    'Could I get that without any added sweetener?': 'هل يمكنني الحصول عليه بدون أي محلي مضاف؟',
    'Do you offer plant-based milk alternatives?': 'هل تقدمون بدائل حليب نباتية؟',
    'Is this completely sugar-free?': 'هل هذا خالٍ تماماً من السكر؟',
    'Is this for here or to go?': 'هل هذا للتناول هنا أم للطريق؟',
    "I'll have it here, please.": 'سأتناوله هنا، من فضلك.',
    'Could I get this to take away?': 'هل يمكنني أخذ هذا معي؟',
    'Is there a table available inside?': 'هل توجد طاولة متاحة بالداخل؟',
    'Can I sit outside on the terrace?': 'هل يمكنني الجلوس بالخارج في التراس؟',
    'Do you have Wi-Fi here?': 'هل لديكم واي فاي هنا؟',
    'Could you bring it to my table?': 'هل يمكن أن تحضره إلى طاولتي؟',
    'Is it okay if I sit here?': 'هل يمكنني الجلوس هنا؟',
    "I'd like to take this with me, please.": 'أريد أن آخذ هذا معي، من فضلك.',
    'Could I get a cup holder for these?': 'هل يمكنني الحصول على حامل أكواب لهذه؟',
    "I think this isn't what I ordered.": 'أعتقد أن هذا ليس ما طلبته.',
    'Could I get some extra napkins, please?': 'هل يمكنني الحصول على مناديل إضافية، من فضلك؟',
    'Sorry, could you remake this one?': 'آسف، هل يمكن إعادة تحضير هذا؟',
    'This coffee seems a bit cold.': 'هذه القهوة تبدو باردة قليلاً.',
    'Could I get a straw, please?': 'هل يمكنني الحصول على ماصة، من فضلك؟',
    'I ordered this without sugar, actually.': 'لقد طلبت هذا بدون سكر في الواقع.',
    'Could you check if this is the right size?': 'هل يمكن أن تتحقق إذا كان هذا هو الحجم الصحيح؟',
    'Sorry, I think you gave me the wrong drink.': 'آسف، أعتقد أنك أعطيتني المشروب الخطأ.',
    'Could I get some more hot water, please?': 'هل يمكنني الحصول على المزيد من الماء الساخن، من فضلك؟',
    'This seems too strong for me — could you add more milk?': 'هذا يبدو قوياً جداً بالنسبة لي — هل يمكن إضافة المزيد من الحليب؟',
    'Thank you, have a nice day.': 'شكراً لك، أتمنى لك يوماً سعيداً.',
    'That was delicious, thank you.': 'كان ذلك لذيذاً، شكراً لك.',
    'Everything was great, thanks so much.': 'كان كل شيء رائعاً، شكراً جزيلاً.',
    'Thanks for the quick service.': 'شكراً على الخدمة السريعة.',
    'I really enjoyed that, thank you.': 'استمتعت حقاً بذلك، شكراً لك.',
    'Have a good one, thanks again.': 'أتمنى لك يوماً جميلاً، شكراً مرة أخرى.',
    'That hit the spot, thank you.': 'كان ذلك بالضبط ما أحتاجه، شكراً لك.',
    "Thanks, I'll definitely come back.": 'شكراً، سأعود بالتأكيد.',
    'I appreciate it, have a great day.': 'أقدر ذلك، أتمنى لك يوماً رائعاً.',
    'Thank you, that was exactly what I needed.': 'شكراً لك، كان ذلك بالضبط ما احتجته.',
    'What would you recommend for a first-time visitor?': 'بماذا تنصح لزائر جديد؟',
    "What's your personal favorite here?": 'ما هو المفضل لديك شخصياً هنا؟',
    'Could you recommend something not too sweet?': 'هل يمكن أن تنصح بشيء ليس حلواً جداً؟',
    'What do most people order in the morning?': 'ماذا يطلب معظم الناس في الصباح؟',
    "Is there something you'd suggest for someone who loves chocolate?": 'هل هناك شيء تقترحه لشخص يحب الشوكولاتة؟',
    'What pairs well with a croissant?': 'ما الذي يتناسب جيداً مع الكرواسون؟',
    'Could you suggest a good afternoon pick-me-up?': 'هل يمكن أن تقترح مشروباً منعشاً جيداً لفترة الظهيرة؟',
    "What's a popular drink for someone who doesn't like coffee?": 'ما هو المشروب الشائع لشخص لا يحب القهوة؟',
    'Do you have a bestseller I should try?': 'هل لديكم مشروب الأكثر مبيعاً يجب أن أجربه؟',
    'What would you recommend on a hot day like today?': 'بماذا تنصح في يوم حار كهذا اليوم؟',

    'Thank you for inviting me to this interview.': 'شكراً لدعوتي لهذه المقابلة.',
    'Thank you for taking the time to meet with me today.': 'شكراً لتخصيص وقتك لمقابلتي اليوم.',
    'I really appreciate the opportunity to speak with you.': 'أقدر حقاً فرصة التحدث معك.',
    "It's a pleasure to finally meet you in person.": 'من دواعي سروري أن ألتقي بك أخيراً شخصياً.',
    "Thank you for having me — I've been looking forward to this.": 'شكراً لاستضافتي — كنت أتطلع لهذا.',
    "I'm glad we could arrange this interview.": 'يسعدني أننا استطعنا ترتيب هذه المقابلة.',
    'Thank you for considering my application.': 'شكراً للنظر في طلبي.',
    "It's an honor to be interviewing for this role.": 'إنه لشرف أن أتقدم لمقابلة هذا المنصب.',
    'I appreciate you fitting me into your schedule.': 'أقدر أنك خصصت وقتاً لي في جدولك.',
    'Thank you for the warm welcome.': 'شكراً على الترحيب الحار.',
    'I have three years of experience in this field.': 'لدي ثلاث سنوات من الخبرة في هذا المجال.',
    "I've worked in customer service for over five years.": 'عملت في خدمة العملاء لأكثر من خمس سنوات.',
    'My background is mainly in project management.': 'خلفيتي المهنية بشكل أساسي في إدارة المشاريع.',
    "I've held a similar position at my previous company.": 'شغلت منصباً مشابهاً في شركتي السابقة.',
    'I gained a lot of hands-on experience during my last role.': 'اكتسبت الكثير من الخبرة العملية في منصبي الأخير.',
    "I've led a small team for the past two years.": 'قدت فريقاً صغيراً خلال السنتين الماضيتين.',
    'My experience includes both remote and in-office work.': 'تشمل خبرتي العمل عن بعد وفي المكتب.',
    "I've worked across several different industries.": 'عملت في عدة قطاعات مختلفة.',
    'I completed an internship in this exact field last year.': 'أكملت تدريباً في هذا المجال بالضبط العام الماضي.',
    "I've been responsible for managing client accounts since 2022.": 'كنت مسؤولاً عن إدارة حسابات العملاء منذ عام 2022.',
    'I work well both independently and in a team.': 'أعمل بشكل جيد سواء بمفردي أو ضمن فريق.',
    'My greatest strength is solving problems quickly.': 'أكبر نقاط قوتي هي حل المشكلات بسرعة.',
    "I'm known for staying calm under pressure.": 'أنا معروف بالهدوء تحت الضغط.',
    'I pay close attention to detail in everything I do.': 'أهتم بالتفاصيل الدقيقة في كل ما أفعله.',
    "I'm a quick learner and adapt easily to new systems.": 'أتعلم بسرعة وأتكيف بسهولة مع الأنظمة الجديدة.',
    "I'm very organized and rarely miss a deadline.": 'أنا منظم جداً ونادراً ما أفوت موعداً نهائياً.',
    'I communicate clearly, even in stressful situations.': 'أتواصل بوضوح، حتى في المواقف الصعبة.',
    "I'm good at motivating the people around me.": 'أنا جيد في تحفيز من حولي.',
    'I take initiative without needing to be asked.': 'أبادر دون الحاجة لأن يُطلب مني ذلك.',
    "I'm comfortable juggling multiple projects at once.": 'أشعر بالارتياح عند إدارة عدة مشاريع في آنٍ واحد.',
    "I sometimes take on too much at once, but I'm learning to delegate.": 'أحياناً أتحمل الكثير دفعة واحدة، لكنني أتعلم كيفية التفويض.',
    'I used to struggle with public speaking, so I joined a course to improve.': 'كنت أعاني من التحدث أمام الجمهور، لذا التحقت بدورة لتحسين ذلك.',
    'I can be overly critical of my own work.': 'قد أكون شديد النقد تجاه عملي الخاص.',
    "I'm working on saying no when my plate is already full.": 'أعمل على تعلم رفض المهام الإضافية عندما أكون مثقلاً بالفعل.',
    "I used to avoid conflict, but I've learned to address issues directly.": 'كنت أتجنب النزاعات، لكنني تعلمت معالجة المشكلات مباشرة.',
    "I'm still improving my skills with data analysis tools.": 'ما زلت أطور مهاراتي في أدوات تحليل البيانات.',
    'I sometimes spend too long perfecting small details.': 'أحياناً أقضي وقتاً طويلاً في إتقان التفاصيل الصغيرة.',
    "I'm learning to ask for help sooner rather than later.": 'أتعلم طلب المساعدة مبكراً بدلاً من التأخير.',
    'I used to find it hard to switch off after work.': 'كنت أجد صعوبة في الاسترخاء بعد العمل.',
    "I'm working on being more concise in my reports.": 'أعمل على أن أكون أكثر إيجازاً في تقاريري.',
    "I've always admired this company's work in this industry.": 'لطالما أعجبت بعمل هذه الشركة في هذا المجال.',
    "This role matches exactly what I'm looking for in my career.": 'هذا المنصب يتطابق تماماً مع ما أبحث عنه في مسيرتي المهنية.',
    "I'm excited about the direction this company is heading.": 'أنا متحمس للاتجاه الذي تسير فيه هذه الشركة.',
    "Your company's values really align with mine.": 'قيم شركتكم تتوافق حقاً مع قيمي.',
    "I've followed this company's growth for a while now.": 'تابعت نمو هذه الشركة منذ فترة.',
    'This position feels like the natural next step for me.': 'هذا المنصب يبدو كالخطوة التالية الطبيعية بالنسبة لي.',
    "I'm drawn to the team culture I've heard about here.": 'أنجذب إلى ثقافة الفريق التي سمعت عنها هنا.',
    'I want to grow my career somewhere that values innovation.': 'أريد تطوير مسيرتي المهنية في مكان يقدّر الابتكار.',
    "This role would let me use skills I don't get to use enough currently.": 'هذا المنصب سيتيح لي استخدام مهارات لا أستخدمها بما فيه الكفاية حالياً.',
    "I've heard great things about the team I'd be joining.": 'سمعت أشياء رائعة عن الفريق الذي سأنضم إليه.',
    'I work well both independently and as part of a team.': 'أعمل بشكل جيد سواء بمفردي أو كجزء من فريق.',
    'I enjoy collaborating with people from different backgrounds.': 'أستمتع بالتعاون مع أشخاص من خلفيات مختلفة.',
    'I believe the best results come from open communication within a team.': 'أعتقد أن أفضل النتائج تأتي من التواصل المفتوح داخل الفريق.',
    "I've mentored a few junior colleagues in my current role.": 'قمت بتوجيه بعض الزملاء المبتدئين في منصبي الحالي.',
    "I'm comfortable giving and receiving constructive feedback.": 'أشعر بالارتياح عند تقديم وتلقي الملاحظات البناءة.',
    "I try to make sure everyone's voice is heard in a meeting.": 'أحرص على أن يُسمع صوت الجميع في الاجتماع.',
    "I've worked closely with cross-functional teams before.": 'عملت عن قرب مع فرق متعددة الوظائف من قبل.',
    'I enjoy brainstorming solutions together rather than alone.': 'أستمتع بابتكار الحلول جماعياً بدلاً من بمفردي.',
    "I try to support my teammates whenever they're overloaded.": 'أحاول دعم زملائي في الفريق عندما يكونون مثقلين بالعمل.',
    'I value transparency when working toward a shared goal.': 'أقدّر الشفافية عند العمل نحو هدف مشترك.',
    'When I face a difficult problem, I break it down into smaller steps.': 'عندما أواجه مشكلة صعبة، أقسمها إلى خطوات أصغر.',
    'I once resolved a major client complaint under a tight deadline.': 'قمت ذات مرة بحل شكوى كبيرة لعميل ضمن موعد نهائي ضيق.',
    'I stay focused on solutions rather than dwelling on the problem.': 'أبقى مركزاً على الحلول بدلاً من التوقف عند المشكلة.',
    'I always look for the root cause before reacting.': 'أبحث دائماً عن السبب الجذري قبل التصرف.',
    "I've learned to stay flexible when plans suddenly change.": 'تعلمت أن أبقى مرناً عندما تتغير الخطط فجأة.',
    'I try to view setbacks as opportunities to improve.': 'أحاول أن أرى النكسات كفرص للتحسن.',
    'I once had to manage a project after losing a key team member.': 'اضطررت ذات مرة لإدارة مشروع بعد فقدان عضو أساسي في الفريق.',
    'I ask clarifying questions early to avoid bigger issues later.': 'أطرح أسئلة توضيحية مبكراً لتجنب مشكلات أكبر لاحقاً.',
    'I stay calm and prioritize when several things go wrong at once.': 'أبقى هادئاً وأرتب الأولويات عندما تسوء عدة أمور في آنٍ واحد.',
    'I usually involve my team when solving a complex problem.': 'عادة ما أُشرك فريقي عند حل مشكلة معقدة.',
    'Could you tell me more about the salary range for this role?': 'هل يمكن أن تخبرني المزيد عن نطاق الراتب لهذا المنصب؟',
    'What does the benefits package typically include?': 'ماذا تتضمن عادةً حزمة المزايا؟',
    'Is remote work an option for this position?': 'هل العمل عن بعد خيار متاح لهذا المنصب؟',
    'What would the working hours look like?': 'كيف ستبدو ساعات العمل؟',
    'When would you expect the successful candidate to start?': 'متى تتوقعون أن يبدأ المرشح الناجح؟',
    'Are there opportunities for growth within the company?': 'هل هناك فرص للنمو داخل الشركة؟',
    'How is performance usually reviewed here?': 'كيف يتم تقييم الأداء عادة هنا؟',
    'Is relocation assistance offered for this role?': 'هل تقدَّم مساعدة الانتقال لهذا المنصب؟',
    'What does a typical career path look like from this position?': 'كيف يبدو المسار الوظيفي المعتاد من هذا المنصب؟',
    'Could you walk me through the next steps in the hiring process?': 'هل يمكن أن توضح لي الخطوات التالية في عملية التوظيف؟',
    'What does success look like in this role after the first year?': 'كيف يبدو النجاح في هذا المنصب بعد السنة الأولى؟',
    'What do you enjoy most about working here?': 'ما الذي تستمتع به أكثر في العمل هنا؟',
    "How would you describe the team's day-to-day dynamic?": 'كيف تصف ديناميكية الفريق اليومية؟',
    'What are the biggest challenges facing the team right now?': 'ما أكبر التحديات التي يواجهها الفريق حالياً؟',
    'How does the company support professional development?': 'كيف تدعم الشركة التطور المهني؟',
    "What's the management style like on this team?": 'كيف هو أسلوب الإدارة في هذا الفريق؟',
    'Is there anything about my background that gives you concern?': 'هل هناك أي شيء في خلفيتي يثير قلقك؟',
    'How has this role evolved over the past few years?': 'كيف تطور هذا المنصب خلال السنوات القليلة الماضية؟',
    'What made you decide to join this company?': 'ما الذي جعلك تقرر الانضمام لهذه الشركة؟',
    'What are the next steps after this interview?': 'ما هي الخطوات التالية بعد هذه المقابلة؟',
    'When can I expect to hear back from you?': 'متى يمكنني أن أتوقع الرد منكم؟',
    'Thank you again for this opportunity.': 'شكراً مرة أخرى على هذه الفرصة.',
    "I'm very enthusiastic about the possibility of joining your team.": 'أنا متحمس جداً لإمكانية الانضمام إلى فريقكم.',
    'Please let me know if you need any further information from me.': 'أخبروني إذا احتجتم أي معلومات إضافية مني.',
    'I look forward to hearing from you soon.': 'أتطلع لسماع ردكم قريباً.',
    "Thank you for your time today — it's been a pleasure.": 'شكراً لوقتكم اليوم — كانت تجربة ممتعة.',
    "I'm confident I could contribute a lot to this role.": 'أنا واثق أنني أستطيع تقديم الكثير لهذا المنصب.',
    "Is there anything else you'd like to know about me?": 'هل هناك أي شيء آخر تودون معرفته عني؟',
    'Thanks again, I really enjoyed our conversation.': 'شكراً مرة أخرى، استمتعت حقاً بحديثنا.',
    'I appreciate your consideration and look forward to next steps.': 'أقدر اهتمامكم وأتطلع للخطوات التالية.',

    'Where is the check-in counter for this flight?': 'أين هو مكتب تسجيل الوصول لهذه الرحلة؟',
    'Could I check in for my flight, please?': 'هل يمكنني تسجيل الوصول لرحلتي، من فضلك؟',
    "Here's my passport and booking reference.": 'هذا جواز سفري ورقم الحجز.',
    'Is online check-in available for this flight?': 'هل تسجيل الوصول عبر الإنترنت متاح لهذه الرحلة؟',
    'Could I get a boarding pass, please?': 'هل يمكنني الحصول على بطاقة صعود الطائرة، من فضلك؟',
    'How many bags am I allowed to check in?': 'كم عدد الحقائب المسموح بتسجيلها؟',
    'Is there a fee for checking an extra bag?': 'هل هناك رسوم لتسجيل حقيبة إضافية؟',
    'Could you confirm my flight number, please?': 'هل يمكن تأكيد رقم رحلتي، من فضلك؟',
    'What time does check-in close for this flight?': 'متى يغلق تسجيل الوصول لهذه الرحلة؟',
    'Could I check in a bit early?': 'هل يمكنني تسجيل الوصول مبكراً قليلاً؟',
    'Where is airport security located?': 'أين يقع أمن المطار؟',
    'Do I need to remove my laptop from my bag?': 'هل يجب أن أخرج حاسوبي المحمول من حقيبتي؟',
    'Which gate does this flight board from?': 'من أي بوابة تُقلع هذه الرحلة؟',
    'What time does boarding start?': 'متى يبدأ الصعود إلى الطائرة؟',
    'Is priority boarding available for this flight?': 'هل الصعود ذو الأولوية متاح لهذه الرحلة؟',
    'Could you tell me where gate B12 is?': 'هل يمكن أن تخبرني أين تقع البوابة B12؟',
    'Is this the line for security?': 'هل هذا هو طابور الأمن؟',
    'Do I need to take off my shoes here?': 'هل يجب أن أخلع حذائي هنا؟',
    'How long is the wait through security today?': 'كم مدة الانتظار عبر الأمن اليوم؟',
    'Excuse me, is this the gate for the London flight?': 'عفواً، هل هذه بوابة رحلة لندن؟',
    'I would like a window seat, please.': 'أريد مقعداً بجانب النافذة، من فضلك.',
    'Could I get an aisle seat instead?': 'هل يمكنني الحصول على مقعد بجانب الممر بدلاً من ذلك؟',
    'Is it possible to sit next to my family?': 'هل يمكن الجلوس بجانب عائلتي؟',
    'Are there any exit row seats available?': 'هل هناك مقاعد متاحة بجانب مخرج الطوارئ؟',
    'Could I upgrade my seat for this flight?': 'هل يمكنني ترقية مقعدي لهذه الرحلة؟',
    'Is there extra legroom available on this flight?': 'هل هناك مساحة إضافية للأرجل في هذه الرحلة؟',
    'Could you check if a middle seat is free?': 'هل يمكن التحقق إذا كان هناك مقعد أوسط شاغر؟',
    "I'd prefer not to sit near the back, if possible.": 'أفضل ألا أجلس بالقرب من الخلف، إن أمكن.',
    'Can we be seated together as a family?': 'هل يمكننا الجلوس معاً كعائلة؟',
    'Is there a fee to choose my seat in advance?': 'هل هناك رسوم لاختيار مقعدي مسبقاً؟',
    'How long is the layover in Istanbul?': 'كم مدة التوقف في إسطنبول؟',
    'Do I need to collect my bags during the layover?': 'هل يجب أن أستلم حقائبي أثناء التوقف؟',
    'Is there enough time to make my connecting flight?': 'هل هناك وقت كافٍ للحاق برحلتي المتصلة؟',
    'Which terminal does my connecting flight depart from?': 'من أي صالة تُقلع رحلتي المتصلة؟',
    'Do I need to go through security again for my next flight?': 'هل يجب أن أمر بالأمن مرة أخرى لرحلتي التالية؟',
    'Is there a lounge I can wait in during the layover?': 'هل هناك صالة انتظار يمكنني الجلوس فيها أثناء التوقف؟',
    'What happens if I miss my connecting flight?': 'ماذا يحدث إذا فاتتني رحلتي المتصلة؟',
    'Is my luggage checked through to my final destination?': 'هل أمتعتي مسجلة حتى وجهتي النهائية؟',
    'How do I find my connecting gate?': 'كيف أجد بوابة رحلتي المتصلة؟',
    'Is there a shuttle between terminals here?': 'هل هناك حافلة تنقل بين الصالات هنا؟',
    'Could you help me find my luggage?': 'هل يمكن أن تساعدني في إيجاد أمتعتي؟',
    "My suitcase hasn't arrived on the belt yet.": 'لم تصل حقيبتي بعد إلى الحزام الناقل.',
    'Where is the baggage claim for this flight?': 'أين استلام الأمتعة لهذه الرحلة؟',
    'I think my bag has been damaged.': 'أعتقد أن حقيبتي قد تضررت.',
    'Is there a lost and found for luggage here?': 'هل يوجد مكتب للمفقودات هنا؟',
    'How much does an extra checked bag cost?': 'كم تكلف حقيبة مسجلة إضافية؟',
    'Could I get a luggage cart, please?': 'هل يمكنني الحصول على عربة أمتعة، من فضلك؟',
    'My bag seems to be missing — who should I speak to?': 'يبدو أن حقيبتي مفقودة — مع من يجب أن أتحدث؟',
    'Is this the right carousel for flight 245?': 'هل هذا هو الحزام الصحيح للرحلة 245؟',
    'Could you help me wrap my suitcase?': 'هل يمكن أن تساعدني في تغليف حقيبتي؟',
    'Has this flight been delayed?': 'هل تأخرت هذه الرحلة؟',
    "What's causing the delay?": 'ما سبب التأخير؟',
    'Could you tell me the new departure time?': 'هل يمكن أن تخبرني بموعد الإقلاع الجديد؟',
    'Is there a chance this flight will be cancelled?': 'هل هناك احتمال أن تُلغى هذه الرحلة؟',
    'Can I be rebooked onto an earlier flight?': 'هل يمكن إعادة حجزي على رحلة أبكر؟',
    'Will I be compensated for this delay?': 'هل سأُعوَّض عن هذا التأخير؟',
    'Is there a hotel voucher available for this overnight delay?': 'هل يتوفر قسيمة فندق لهذا التأخير الليلي؟',
    'Could you update me if the gate changes?': 'هل يمكن إبلاغي إذا تغيرت البوابة؟',
    "How will I be notified if there's a further delay?": 'كيف سيتم إعلامي إذا حدث تأخير إضافي؟',
    'Is there another flight I could take today instead?': 'هل هناك رحلة أخرى يمكنني أخذها اليوم بدلاً من ذلك؟',
    'Do I need to fill out a customs form?': 'هل يجب أن أملأ استمارة جمركية؟',
    'Where is the immigration counter?': 'أين مكتب الهجرة؟',
    'How long am I allowed to stay with this visa?': 'كم المدة المسموح لي بالبقاء بهذه التأشيرة؟',
    "Do I need to declare anything I'm carrying?": 'هل يجب أن أصرّح بأي شيء أحمله؟',
    'Is this the correct line for visitors?': 'هل هذا هو الطابور الصحيح للزوار؟',
    'Could you stamp my passport, please?': 'هل يمكن أن تختم جواز سفري، من فضلك؟',
    "What's the purpose of your visit, they asked me?": 'ما هو غرض زيارتك، سألوني؟',
    'Do I need a return ticket to enter the country?': 'هل أحتاج تذكرة عودة لدخول البلاد؟',
    'Where do I collect my baggage after immigration?': 'أين أستلم أمتعتي بعد الهجرة؟',
    'Is there anything I need to pay at customs?': 'هل هناك أي شيء يجب أن أدفعه في الجمارك؟',
    'Excuse me, where is the nearest restroom?': 'عفواً، أين أقرب دورة مياه؟',
    'Could you point me toward the food court?': 'هل يمكن أن ترشدني إلى منطقة المطاعم؟',
    'Where can I find a currency exchange counter?': 'أين أجد مكتب صرافة؟',
    'Is there a pharmacy inside the airport?': 'هل هناك صيدلية داخل المطار؟',
    'Which way is the exit to the taxi stand?': 'أين طريق الخروج إلى موقف سيارات الأجرة؟',
    'Where can I charge my phone around here?': 'أين يمكنني شحن هاتفي هنا؟',
    'Is there an ATM nearby?': 'هل هناك جهاز صراف آلي قريب؟',
    'Could you show me the way to gate 22?': 'هل يمكن أن تريني الطريق إلى البوابة 22؟',
    'Where is the information desk?': 'أين مكتب الاستعلامات؟',
    'Is there a quiet area where I can rest?': 'هل هناك منطقة هادئة يمكنني الراحة فيها؟',
    'Could you recommend a hotel close to the airport?': 'هل يمكن أن تنصح بفندق قريب من المطار؟',
    'Is there a shuttle to the hotels nearby?': 'هل هناك حافلة إلى الفنادق القريبة؟',
    'How do I get a taxi from here?': 'كيف أحصل على سيارة أجرة من هنا؟',
    'Is public transport available to the city center?': 'هل النقل العام متاح إلى وسط المدينة؟',
    'Could you help me book a rental car?': 'هل يمكن أن تساعدني في حجز سيارة مستأجرة؟',
    "What's the best way to get downtown from here?": 'ما أفضل طريقة للوصول إلى وسط المدينة من هنا؟',
    'Is there a train that goes directly to the city?': 'هل هناك قطار يذهب مباشرة إلى المدينة؟',
    'How long does it take to reach the hotel from here?': 'كم يستغرق الوصول إلى الفندق من هنا؟',
    'Could you write the hotel address down for the driver?': 'هل يمكن أن تكتب عنوان الفندق للسائق؟',
    'Is it safe to take a taxi at this hour?': 'هل من الآمن أخذ سيارة أجرة في هذه الساعة؟',
    'Is this your first time visiting this country?': 'هل هذه أول مرة تزور فيها هذا البلد؟',
    'Are you traveling for business or pleasure?': 'هل تسافر للعمل أم للسياحة؟',
    'How long are you planning to stay?': 'كم من الوقت تخطط للبقاء؟',
    'Is this a direct flight or do you have a connection?': 'هل هذه رحلة مباشرة أم لديك رحلة متصلة؟',
    'Have you traveled this route before?': 'هل سافرت على هذا الطريق من قبل؟',
    "What's the best thing about traveling for you?": 'ما هو أفضل شيء في السفر بالنسبة لك؟',
    'Do you travel often for work?': 'هل تسافر كثيراً للعمل؟',
    'What made you choose this destination?': 'ما الذي جعلك تختار هذه الوجهة؟',
    'Are you excited about this trip?': 'هل أنت متحمس لهذه الرحلة؟',
    'Safe travels — I hope you enjoy your trip.': 'رحلة آمنة — أتمنى أن تستمتع برحلتك.',

    "Let's begin by reviewing last quarter's results.": 'لنبدأ بمراجعة نتائج الربع الماضي.',
    'Thank you all for joining on such short notice.': 'شكراً لكم جميعاً على الانضمام رغم قصر المهلة.',
    "Let's get started, since everyone's here now.": 'لنبدأ الآن بما أن الجميع حاضر.',
    "I'd like to welcome our new team members before we begin.": 'أود أن أرحب بأعضاء الفريق الجدد قبل أن نبدأ.',
    "Let's kick things off with a quick recap of last week.": 'لنبدأ بملخص سريع للأسبوع الماضي.',
    "Shall we get started with today's agenda?": 'هل نبدأ بجدول أعمال اليوم؟',
    'Thanks everyone for making time for this meeting.': 'شكراً للجميع على تخصيص الوقت لهذا الاجتماع.',
    "Let's dive straight into today's main topic.": 'لندخل مباشرة في موضوع اليوم الرئيسي.',
    'Before we start, does anyone have anything urgent to raise?': 'قبل أن نبدأ، هل لدى أحد أي أمر عاجل يريد طرحه؟',
    "Let's open the floor with a brief round of updates.": 'لنفتح النقاش بجولة موجزة من التحديثات.',
    "I'd like to add one point to the agenda.": 'أود إضافة نقطة واحدة إلى جدول الأعمال.',
    'Could we move this item further down the agenda?': 'هل يمكن تأجيل هذا البند لأسفل جدول الأعمال؟',
    "Let's stick closely to the agenda to save time.": 'لنلتزم بجدول الأعمال بدقة لتوفير الوقت.',
    'We have three items to cover today.': 'لدينا ثلاثة بنود لتغطيتها اليوم.',
    "Let's table that discussion for our next meeting.": 'لنؤجل تلك المناقشة لاجتماعنا القادم.',
    'Can we revisit the agenda for a moment?': 'هل يمكننا مراجعة جدول الأعمال للحظة؟',
    'I think we should prioritize the budget item first.': 'أعتقد أنه يجب علينا إعطاء الأولوية لبند الميزانية أولاً.',
    "Let's skip ahead to the next agenda item.": 'لننتقل إلى بند جدول الأعمال التالي.',
    "We're running short on time, so let's focus on the essentials.": 'لدينا وقت قصير، لذا لنركز على الأساسيات.',
    "Is there anything missing from today's agenda?": 'هل هناك أي شيء ناقص من جدول أعمال اليوم؟',
    'As you can see from this chart, sales have grown steadily.': 'كما ترون من هذا الرسم البياني، نمت المبيعات بشكل مطرد.',
    'Let me walk you through the numbers from last month.': 'دعوني أشرح لكم الأرقام من الشهر الماضي.',
    'This slide summarizes our key findings so far.': 'تلخص هذه الشريحة أهم نتائجنا حتى الآن.',
    'The data clearly shows a shift in customer behavior.': 'تظهر البيانات بوضوح تغيراً في سلوك العملاء.',
    "Let's take a closer look at this trend.": 'دعونا نلقِ نظرة أقرب على هذا الاتجاه.',
    'According to our latest report, revenue is up twelve percent.': 'وفقاً لأحدث تقرير لدينا، ارتفعت الإيرادات بنسبة اثني عشر بالمئة.',
    "I'll share my screen to show you the full breakdown.": 'سأشارك شاشتي لأريكم التفاصيل الكاملة.',
    'These figures reflect our performance over the last quarter.': 'تعكس هذه الأرقام أداءنا خلال الربع الماضي.',
    'Let me highlight the most important takeaway from this slide.': 'دعوني أسلط الضوء على أهم استنتاج من هذه الشريحة.',
    "This graph illustrates where we're losing the most customers.": 'يوضح هذا الرسم البياني أين نخسر معظم عملائنا.',
    'Could you clarify what you mean by that?': 'هل يمكن أن توضح ما تقصده بذلك؟',
    'Sorry, could you repeat that last point?': 'آسف، هل يمكن أن تكرر تلك النقطة الأخيرة؟',
    'When you say "next quarter," do you mean this fiscal year?': 'عندما تقول "الربع القادم"، هل تقصد هذه السنة المالية؟',
    'Could you explain how that number was calculated?': 'هل يمكن أن توضح كيف تم حساب ذلك الرقم؟',
    "I'm not sure I followed — could you elaborate?": 'لست متأكداً أنني فهمت — هل يمكن أن تفصّل أكثر؟',
    'What exactly do you mean by "scaling faster"?': 'ماذا تقصد بالضبط بـ"التوسع بشكل أسرع"؟',
    'Could you give an example to illustrate that point?': 'هل يمكن أن تعطي مثالاً لتوضيح تلك النقطة؟',
    'Just to confirm, are we changing the deadline or the scope?': 'للتأكيد فقط، هل نغيّر الموعد النهائي أم النطاق؟',
    'Could you break that down a bit further for me?': 'هل يمكن أن تشرح ذلك بتفصيل أكبر لي؟',
    'Sorry, I want to make sure I understood that correctly.': 'آسف، أريد التأكد من أنني فهمت ذلك بشكل صحيح.',
    'I think we should postpone this decision.': 'أعتقد أنه يجب علينا تأجيل هذا القرار.',
    'I see it a little differently, if I may.': 'أراها بشكل مختلف قليلاً، إذا سمحت لي.',
    "I'm not entirely convinced this is the right approach.": 'لست مقتنعاً تماماً أن هذا هو النهج الصحيح.',
    "That's a fair point, but I'd like to offer another perspective.": 'هذه نقطة وجيهة، لكنني أود تقديم وجهة نظر أخرى.',
    'I understand the reasoning, but I have some reservations.': 'أتفهم المنطق، لكن لدي بعض التحفظات.',
    'Could we consider an alternative before finalizing this?': 'هل يمكن أن ننظر في بديل قبل إنهاء هذا؟',
    "I'd push back slightly on that assumption.": 'أود أن أعترض قليلاً على ذلك الافتراض.',
    'I respect that view, though I lean toward a different plan.': 'أحترم تلك الرؤية، رغم أنني أميل لخطة مختلفة.',
    "Let's make sure we've considered the risks before agreeing.": 'لنتأكد أننا نظرنا في المخاطر قبل الموافقة.',
    "I'm hesitant to commit to that timeline just yet.": 'أتردد في الالتزام بذلك الجدول الزمني الآن.',
    "I'd like to propose we move the launch date forward.": 'أود أن أقترح تقديم موعد الإطلاق.',
    'My suggestion would be to test this with a smaller group first.': 'اقتراحي هو اختبار هذا مع مجموعة أصغر أولاً.',
    "Let's go with option two, given the budget constraints.": 'لنذهب مع الخيار الثاني، نظراً لقيود الميزانية.',
    'I recommend we revisit this decision next month.': 'أوصي بأن نعيد النظر في هذا القرار الشهر القادم.',
    'Shall we vote on this before moving on?': 'هل نصوّت على هذا قبل المتابعة؟',
    'I think the safest option is to delay by one week.': 'أعتقد أن الخيار الأكثر أماناً هو التأجيل لمدة أسبوع.',
    "Let's agree on a plan and commit to it today.": 'لنتفق على خطة ونلتزم بها اليوم.',
    "I'd like to put forward a different solution.": 'أود طرح حل مختلف.',
    'Given the data, I think we should proceed with the second option.': 'بناءً على البيانات، أعتقد أنه يجب علينا المضي في الخيار الثاني.',
    "Let's finalize this decision before the end of the meeting.": 'لننهِ هذا القرار قبل نهاية الاجتماع.',
    "Let's schedule a follow-up meeting for next week.": 'لنحدد موعداً لاجتماع متابعة الأسبوع القادم.',
    "I'll take ownership of the client report.": 'سأتولى مسؤولية تقرير العميل.',
    'Could you follow up with the design team by Friday?': 'هل يمكن أن تتابع مع فريق التصميم بحلول الجمعة؟',
    "Let's assign clear owners to each action item.": 'لنحدد مسؤولين واضحين لكل بند إجرائي.',
    "I'll send everyone a summary after this call.": 'سأرسل للجميع ملخصاً بعد هذه المكالمة.',
    'Who can take the lead on this task?': 'من يمكنه تولي قيادة هذه المهمة؟',
    "Let's make sure each action item has a deadline attached.": 'لنتأكد أن كل بند إجرائي له موعد نهائي محدد.',
    "I'll coordinate with finance on the budget approval.": 'سأنسق مع قسم المالية بخصوص الموافقة على الميزانية.',
    'Could someone volunteer to draft the proposal?': 'هل يمكن لأحد أن يتطوع لصياغة المقترح؟',
    "Let's confirm responsibilities before we wrap up.": 'لنؤكد المسؤوليات قبل أن ننهي الاجتماع.',
    "What's a realistic deadline for this project?": 'ما هو الموعد النهائي الواقعي لهذا المشروع؟',
    'Can we commit to delivering this by the end of the month?': 'هل يمكننا الالتزام بتسليم هذا بحلول نهاية الشهر؟',
    "I'm concerned this timeline might be too tight.": 'أنا قلق أن يكون هذا الجدول الزمني ضيقاً جداً.',
    "Let's build in some buffer time before the deadline.": 'لنضف بعض الوقت الاحتياطي قبل الموعد النهائي.',
    'When do you expect the first draft to be ready?': 'متى تتوقع أن تكون المسودة الأولى جاهزة؟',
    'Is there any flexibility in the delivery date?': 'هل هناك أي مرونة في تاريخ التسليم؟',
    'We need to move faster if we want to hit this deadline.': 'نحتاج للتحرك بشكل أسرع إذا أردنا الوصول لهذا الموعد النهائي.',
    "Let's set a checkpoint halfway through the timeline.": 'لنضع نقطة مراجعة في منتصف الجدول الزمني.',
    'I think we can realistically finish this in three weeks.': 'أعتقد أنه يمكننا واقعياً إنهاء هذا خلال ثلاثة أسابيع.',
    'Could we push the deadline back by a few days?': 'هل يمكن تأجيل الموعد النهائي بضعة أيام؟',
    "Let's wrap up with a quick summary of today's decisions.": 'لننهِ بملخص سريع لقرارات اليوم.',
    'Does anyone have any final questions before we close?': 'هل لدى أحد أي أسئلة أخيرة قبل أن ننهي؟',
    "I think we've covered everything on today's agenda.": 'أعتقد أننا غطينا كل شيء في جدول أعمال اليوم.',
    'Thanks everyone, this was a productive discussion.': 'شكراً للجميع، كانت هذه مناقشة مثمرة.',
    "Let's end there and pick this up again next week.": 'لننهِ هنا ونكمل هذا مرة أخرى الأسبوع القادم.',
    "Before we finish, let's confirm our next steps.": 'قبل أن ننهي، لنؤكد خطواتنا التالية.',
    "I'll send the meeting notes out by this afternoon.": 'سأرسل ملاحظات الاجتماع بحلول بعد ظهر اليوم.',
    'Thank you all for your input today.': 'شكراً لكم جميعاً على مساهماتكم اليوم.',
    "Let's close the meeting here unless anyone objects.": 'لننهِ الاجتماع هنا ما لم يعترض أحد.',
    "Great discussion, everyone — let's reconvene next week.": 'مناقشة رائعة، جميعاً — لنجتمع مرة أخرى الأسبوع القادم.',
    "I'll follow up with an email summarizing our decisions.": 'سأتابع برسالة إلكترونية تلخص قراراتنا.',
    'Please let me know if I missed anything in the notes.': 'أخبروني إذا فاتني أي شيء في الملاحظات.',
    "I'll circulate the updated timeline by tomorrow.": 'سأعمم الجدول الزمني المحدث بحلول الغد.',
    'Feel free to reach out if anything is unclear.': 'لا تترددوا في التواصل إذا كان هناك أي شيء غير واضح.',
    "I'll loop in the rest of the team on this thread.": 'سأشرك بقية الفريق في هذا الموضوع.',
    "Let's keep each other updated as things progress.": 'لنبقِ بعضنا البعض على اطلاع مع تقدم الأمور.',
    "I'll share the recording for anyone who couldn't join.": 'سأشارك التسجيل لمن لم يستطع الانضمام.',
    'Please review the document before our next call.': 'يرجى مراجعة المستند قبل مكالمتنا القادمة.',
    "I'll follow up individually with anyone who has questions.": 'سأتابع بشكل فردي مع أي شخص لديه أسئلة.',
    'Looking forward to our next update on this.': 'أتطلع لتحديثنا القادم حول هذا الموضوع.',

}

# Build one lookup of every English line -> Arabic, across sentences AND
# all conversation lines, so any "Translate" button resolves instantly.
_TRANSLATION_LOOKUP = dict(LESSON_TRANSLATIONS)
for _lvl in SENTENCE_BANK.values():
    for _s in _lvl:
        _TRANSLATION_LOOKUP[_s["en"]] = _s["ar"]
for _cat in SHADOW_CATEGORIES:
    for _p in _cat["phrases"]:
        _TRANSLATION_LOOKUP[_p["en"]] = _p["ar"]
for _c in CONVERSATIONS:
    for _node in _c["nodes"]:
        _TRANSLATION_LOOKUP[_node["npc"]["en"]] = _node["npc"]["ar"]
        for _r in _node.get("replies", []):
            _TRANSLATION_LOOKUP[_r["en"]] = _r["ar"]
for _convs in SPRINT_CONVS_BY_SPRINT.values():
    for _day in _convs.values():
        for _node in _day["nodes"]:
            _TRANSLATION_LOOKUP[_node["npc"]["en"]] = _node["npc"]["ar"]
            for _r in _node.get("replies", []):
                _TRANSLATION_LOOKUP[_r["en"]] = _r["ar"]


@app.post("/api/translate")
def translate(data: TranslateIn, request: Request, user: User = Depends(get_current_user)):
    """
    Look up a baked-in translation first -- instant, free, offline, and
    covers every pre-authored phrase in Lessons/Shadow/Conversations (any
    miss there is a real content gap, not expected). Falls back to a live
    Gemini translation ONLY for Max users when the lookup misses, which is
    what makes Translate work on AI Roleplay's replies -- those are
    generated fresh every turn and can never live in the static dictionary.
    Free/Pro users see byte-identical behavior to before this fallback existed.
    """
    text = data.text.strip()
    ar = _TRANSLATION_LOOKUP.get(text, "")
    if ar:
        return {"translated": ar, "lang": "ar", "found": True}
    if text and GEMINI_CONFIGURED and user.is_premium and user.plan_tier == "max":
        rate_limit(request, "translate-ai", limit=40, window=300)
        try:
            ar = call_gemini_translate(text[:800])
        except HTTPException:
            ar = ""   # fail quiet -- same "not found" shape the frontend already handles
        return {"translated": ar, "lang": "ar", "found": bool(ar)}
    return {"translated": "", "lang": "ar", "found": False}


# ---- Scripted conversations (branching, no API) ----
def _conv_public(c: dict, locked: bool, recommended: bool = False) -> dict:
    """Scenario card info. Nodes are only sent when actually opened."""
    return {"id": c["id"], "title": c["title"], "level": c["level"],
            "emoji": c["emoji"], "is_premium": c["is_premium"], "locked": locked,
            "setting": "" if locked else c["setting"],
            "goal": "" if locked else c["goal"],
            # A learning-goal-path hint (see GOAL_TAGS) -- unrelated to the
            # "goal" key above, which is this scenario's own in-story
            # objective text and predates goal paths by a long way.
            "recommended": recommended}


@app.get("/api/scenarios")
def list_scenarios(user: User = Depends(get_current_user)):
    goal_tags = GOAL_TAGS.get(user.goal, {}) if user.goal else {}
    recommended_ids = goal_tags.get("conversations", set())
    out = []
    for c in CONVERSATIONS:
        locked = c["is_premium"] and not user.is_premium
        out.append(_conv_public(c, locked, recommended=c["id"] in recommended_ids))
    # ai_ready stays True so the frontend "conversations off" banner never shows.
    return {"ai_ready": True, "scenarios": out}


@app.get("/api/conversation/{conv_id}")
def get_conversation(conv_id: str, user: User = Depends(get_current_user),
                     session: Session = Depends(get_session)):
    """
    Returns the full node tree for one conversation, so the browser can run
    the whole branching dialogue with zero further server calls.
    Handles both standalone scenarios and Sprint-day conversations.
    """
    if conv_id.startswith("sprintday"):
        # New format: "sprintday-{sprint_id}-{day}", e.g. "sprintday-biz14-3".
        # The old bare "sprintday{day}" (no sprint_id) still works as an
        # alias for the Core Sprint, in case any client has it cached.
        rest = conv_id[len("sprintday"):]
        if rest.startswith("-"):
            sprint_id, _, day_str = rest[1:].rpartition("-")
        else:
            sprint_id, day_str = DEFAULT_SPRINT_ID, rest
        try:
            day_num = int(day_str)
        except ValueError:
            raise HTTPException(404, "Conversation not found.")
        if sprint_id not in SPRINTS:
            raise HTTPException(404, "Conversation not found.")
        conv = SPRINT_CONVS_BY_SPRINT[sprint_id].get(day_num)
        if not conv:
            raise HTTPException(404, "Conversation not found.")
        if not user.is_premium:
            raise HTTPException(403, "The Sprint is a Pro program.")
        state = _sprint_state(user, sprint_id, session)
        if not state["enrolled"]:
            raise HTTPException(400, "Start the Sprint first.")
        if day_num > state["unlocked_through"]:
            raise HTTPException(403, "That day hasn't unlocked yet.")
        if day_num not in state.get("drill_done_days", []):
            raise HTTPException(400, "Finish today's phrase drill first.")
        return {"id": conv_id, "setting": conv["setting"], "goal": conv["goal"],
                "start": conv["start"], "nodes": conv["nodes"]}

    c = CONVERSATION_BY_ID.get(conv_id)
    if not c:
        raise HTTPException(404, "Conversation not found.")
    if c["is_premium"] and not user.is_premium:
        raise HTTPException(403, "This conversation is for Pro members.")
    return {"id": c["id"], "title": c["title"], "emoji": c["emoji"],
            "setting": c["setting"], "goal": c["goal"],
            "start": c["start"], "nodes": c["nodes"]}


@app.get("/api/ai/status")
def ai_status(user: User = Depends(get_current_user)):
    # Reports whether the server owner has actually set GEMINI_API_KEY yet --
    # used by AI Roleplay and Songs to show "not turned on yet" instead of a
    # raw error. Scripted conversations never call this; they're fully
    # offline and don't need it.
    return {"ready": GEMINI_CONFIGURED}


class RoleplayTurnIn(BaseModel):
    scenario: str = ""     # optional persona/topic, e.g. "Ordering coffee at a busy cafe"
    history: list[dict] = []   # [{role: "user"|"ai", text: "..."}, ...] so far
    message: str


@app.post("/api/roleplay/reply")
def roleplay_reply(data: RoleplayTurnIn, request: Request, user: User = Depends(require_max)):
    """
    One turn of the free-form AI Roleplay feature (Max only). Stateless --
    the browser sends the whole transcript back each time; see call_gemini.
    """
    rate_limit(request, "roleplay-reply", limit=20, window=300)
    if not GEMINI_CONFIGURED:
        raise HTTPException(503, "AI Roleplay is not configured on this server yet (missing GEMINI_API_KEY).")
    message = data.message.strip()
    if not message:
        raise HTTPException(400, "Say something first.")
    if len(message) > 800:
        raise HTTPException(400, "That message is too long.")
    reply = call_gemini(data.scenario, data.history, message)
    return {"reply": reply}


SONG_LEVELS = {"Beginner", "Intermediate", "Advanced"}


class SongGenerateIn(BaseModel):
    theme: str = ""
    level: str = "Beginner"


@app.post("/api/songs/generate")
def songs_generate(data: SongGenerateIn, request: Request, user: User = Depends(require_max)):
    """
    Generates one short, wholly original practice song (Max only). Nothing
    is persisted -- same stateless, ephemeral pattern as AI Roleplay, just a
    single request/response instead of a back-and-forth conversation.
    """
    rate_limit(request, "songs-generate", limit=12, window=300)
    if not GEMINI_CONFIGURED:
        raise HTTPException(503, "Songs isn't configured on this server yet (missing GEMINI_API_KEY).")
    theme = data.theme.strip()[:80]
    level = data.level.strip() if data.level.strip() in SONG_LEVELS else "Beginner"
    song = call_gemini_song(theme, level)
    return song


class BreakdownIn(BaseModel):
    text: str


@app.post("/api/songs/breakdown")
def songs_breakdown(data: BreakdownIn, request: Request, user: User = Depends(require_max)):
    """
    The connected-speech breakdown for one line (Max only) -- works on real
    or AI-generated lyrics alike. Nothing is persisted.
    """
    rate_limit(request, "songs-breakdown", limit=40, window=300)
    if not GEMINI_CONFIGURED:
        raise HTTPException(503, "This feature isn't configured on this server yet (missing GEMINI_API_KEY).")
    text = data.text.strip()[:200]
    if not text:
        raise HTTPException(400, "Nothing to break down.")
    return call_gemini_breakdown(text)


# ----------------------------------------------------------------------
# 7c. ADMIN ROUTES — manage users, and unlock the Sprint for testing
# ----------------------------------------------------------------------
@app.get("/api/admin/users")
def admin_list_users(admin: User = Depends(require_admin),
                     session: Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    out = []
    for u in users:
        st = _sprint_state(u, DEFAULT_SPRINT_ID, session)
        out.append({
            "id": u.id, "email": u.email, "is_premium": u.is_premium,
            "is_admin": u.is_admin, "created_at": u.created_at.isoformat(),
            "sprint_enrolled": st["enrolled"],
            "sprint_days_done": len(st["completed_days"]) if st["enrolled"] else 0,
        })
    return out


@app.post("/api/admin/users/{user_id}/toggle-premium")
def admin_toggle_premium(user_id: int, admin: User = Depends(require_admin),
                         session: Session = Depends(get_session)):
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    target.is_premium = not target.is_premium
    session.add(target)
    session.commit()
    return {"id": target.id, "is_premium": target.is_premium}


@app.post("/api/admin/users/{user_id}/delete")
def admin_delete_user(user_id: int, admin: User = Depends(require_admin),
                      session: Session = Depends(get_session)):
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    if target.id == admin.id:
        raise HTTPException(400, "You can't delete your own admin account.")
    for row in session.exec(select(Attempt).where(Attempt.user_id == user_id)).all():
        session.delete(row)
    for row in session.exec(select(Enrollment).where(Enrollment.user_id == user_id)).all():
        session.delete(row)
    for row in session.exec(select(DayCompletion).where(DayCompletion.user_id == user_id)).all():
        session.delete(row)
    session.delete(target)
    session.commit()
    return {"deleted": user_id}


@app.post("/api/admin/sprint/unlock-all")
def admin_unlock_all(admin: User = Depends(require_admin),
                     session: Session = Depends(get_session)):
    """
    TESTING ONLY. Enrolls the admin in EVERY Sprint (unlocking whichever one
    would normally be gated too) and backdates each start date so every day
    of every Sprint is unlocked right now. Lets you click through and test
    all of them without waiting, or being blocked by "finish the last one
    first." Doesn't mark any day as *completed* — you still practice each one.
    """
    for sprint_id, sprint_def in SPRINTS.items():
        total_days = len(sprint_def["days"])
        enr = session.exec(
            select(Enrollment).where(Enrollment.user_id == admin.id,
                                     Enrollment.sprint_id == sprint_id)
        ).first()
        backdate = dt.datetime.utcnow() - dt.timedelta(days=total_days)
        if enr:
            enr.started_at = backdate
            session.add(enr)
        else:
            session.add(Enrollment(user_id=admin.id, sprint_id=sprint_id, started_at=backdate))
    session.commit()
    return {sid: _sprint_state(admin, sid, session) for sid in SPRINTS}


@app.post("/api/admin/sprint/reset")
def admin_reset_sprint(admin: User = Depends(require_admin),
                       session: Session = Depends(get_session)):
    """TESTING ONLY. Wipes the admin's own progress in EVERY Sprint to start over."""
    for sprint_id in SPRINTS:
        for model in (Enrollment, DayCompletion, DayConvDone):
            for row in session.exec(
                select(model).where(model.user_id == admin.id, model.sprint_id == sprint_id)
            ).all():
                session.delete(row)
    session.commit()
    return {"reset": True}


# ----------------------------------------------------------------------
# 8. SERVE THE FRONTEND + SECURITY HEADERS
# ----------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"  # stop clickjacking
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "microphone=(self)"
    return response


@app.get("/")
def index():
    # no-cache: the browser must always re-fetch this page. Without it, Chrome
    # can keep serving an old copy of the app after you update index.html,
    # which looks exactly like "my changes did nothing".
    return FileResponse(
        BASE_DIR / "static" / "index.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                 "Pragma": "no-cache"},
    )


_LEGAL_LAST_UPDATED = "July 21, 2026"  # bump this whenever you edit terms/privacy/refund.html


def _serve_legal_page(filename: str) -> HTMLResponse:
    """
    Serves a static legal page (terms/privacy/refund) after filling in the
    {{SUPPORT_EMAIL}} and {{LAST_UPDATED}} placeholders server-side. Keeping
    these as placeholders (instead of a hardcoded email in the HTML) means
    the pages always show whatever SUPPORT_EMAIL/ADMIN_EMAIL you've actually
    configured, on every deploy, with no risk of a stale/fake address.
    """
    html = (BASE_DIR / "static" / filename).read_text()
    html = html.replace("{{SUPPORT_EMAIL}}", SUPPORT_EMAIL).replace("{{LAST_UPDATED}}", _LEGAL_LAST_UPDATED)
    return HTMLResponse(html)


@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    return _serve_legal_page("terms.html")


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    return _serve_legal_page("privacy.html")


@app.get("/refund", response_class=HTMLResponse)
def refund_page():
    return _serve_legal_page("refund.html")


# ----------------------------------------------------------------------
# 8b. PWA — installable "Add to Home Screen" support
# ----------------------------------------------------------------------
# No build step needed: a manifest + a service worker + a few icon sizes
# is all a browser needs to offer installation. Served as plain files
# (like the legal pages above) rather than a StaticFiles mount, since
# that's the pattern this app already uses everywhere else.
@app.get("/manifest.json")
def pwa_manifest():
    return FileResponse(BASE_DIR / "static" / "manifest.json", media_type="application/manifest+json")


@app.get("/sw.js")
def service_worker():
    # No caching on the service worker script itself — the browser needs to
    # notice updates to it promptly (same reasoning as index.html above).
    return FileResponse(
        BASE_DIR / "static" / "sw.js", media_type="application/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/icon-192.png")
def icon_192():
    return FileResponse(BASE_DIR / "static" / "icon-192.png", media_type="image/png")


@app.get("/icon-512.png")
def icon_512():
    return FileResponse(BASE_DIR / "static" / "icon-512.png", media_type="image/png")


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return FileResponse(BASE_DIR / "static" / "apple-touch-icon.png", media_type="image/png")


@app.get("/favicon-32.png")
def favicon_32():
    return FileResponse(BASE_DIR / "static" / "favicon-32.png", media_type="image/png")


@app.get("/favicon-16.png")
def favicon_16():
    return FileResponse(BASE_DIR / "static" / "favicon-16.png", media_type="image/png")


@app.get("/favicon.ico")
def favicon_ico():
    # Some browsers request this exact path regardless of <link rel="icon">.
    return FileResponse(BASE_DIR / "static" / "favicon-32.png", media_type="image/png")


@app.get("/api/debug/config")
def debug_config():
    """
    Safe diagnostic. Shows whether ADMIN_EMAIL loaded, WITHOUT revealing secrets.
    Open http://localhost:8000/api/debug/config in your browser to check setup.
    """
    return {
        "admin_emails_loaded": len(ADMIN_EMAILS),
        "admin_emails": sorted(ADMIN_EMAILS) or "(none set — check your .env file)",
        "frontend_has_admin_button": "adminBtn" in (BASE_DIR / "static" / "index.html").read_text(),
        "env_file_found": (BASE_DIR / ".env").exists(),
    }


# ----------------------------------------------------------------------
# 9. STARTUP BANNER — prints your config so you can see what loaded
# ----------------------------------------------------------------------
def _startup_banner():
    env_found = (BASE_DIR / ".env").exists()
    index_file = BASE_DIR / "static" / "index.html"
    fe_ok = index_file.exists() and "adminBtn" in index_file.read_text()

    print("\n" + "=" * 58)
    print("  SpeakPort — starting up")
    print("=" * 58)
    print(f"  .env file found      : {'YES' if env_found else 'NO  <-- create it: cp .env.example .env'}")
    if ADMIN_EMAILS:
        print(f"  ADMIN_EMAIL(S)       : {', '.join(sorted(ADMIN_EMAILS))}")
        print(f"                         ^ ONLY these emails are admin. Everyone else is not.")
    else:
        print("  ADMIN_EMAIL          : NOT SET  <-- add ADMIN_EMAIL=you@email.com to .env")
    print(f"  Frontend admin button: {'YES' if fe_ok else 'NO  <-- static/index.html is OUT OF DATE'}")
    sprint_summary = ", ".join(f"{sdef['title']} ({len(sdef['days'])}d)" for sdef in SPRINTS.values())
    print(f"  Sprints              : {sprint_summary}   Pass score: {PASS_SCORE}%")
    print(f"  Content              : OFFLINE (no API, no keys, no limits)")
    print(f"    practice sentences : {sum(len(v) for v in SENTENCE_BANK.values())} across "
          f"{len(SENTENCE_BANK)} levels")
    print(f"  Gemini AI (Max: Roleplay + Songs) : {'configured, model=' + GEMINI_MODEL if GEMINI_CONFIGURED else 'NOT configured  <-- add GEMINI_API_KEY to .env to turn it on'}")
    total_sprint_convs = sum(len(c) for c in SPRINT_CONVS_BY_SPRINT.values())
    print(f"    conversations      : {len(CONVERSATIONS)} scenarios + {total_sprint_convs} sprint days")
    print("=" * 58)
    print("  Open http://localhost:8000 in Google Chrome")
    print("=" * 58 + "\n")


_startup_banner()
