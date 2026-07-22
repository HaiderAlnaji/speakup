"""
SpeakUp — English speaking practice app (backend + serves the frontend)

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
# Until these are set, SpeakUp runs in DEMO MODE for password resets: instead
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
# https://speakup-h4k8.onrender.com). Falls back to a same-origin relative
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
PADDLE_ENV = os.getenv("PADDLE_ENV", "sandbox").strip()             # "sandbox" or "production"

# All four must be set for real payments to be live. Until then, SpeakUp
# stays in demo mode: /api/upgrade instantly grants Pro so you can test
# everything locally without a Paddle account. The moment real credentials
# are set (in production), that shortcut automatically closes — see /api/upgrade.
PADDLE_CONFIGURED = bool(PADDLE_API_KEY and PADDLE_WEBHOOK_SECRET
                         and PADDLE_CLIENT_TOKEN and PADDLE_PRICE_ID)

# ----------------------------------------------------------------------
# 1e. PAYMENTS — ZainCash (Iraq's mobile-wallet payment gateway)
# ----------------------------------------------------------------------
# Paddle/Stripe/Lemon Squeezy/Dodo all refuse to onboard sellers based in
# Iraq, so ZainCash is the real payment path for SpeakUp. It settles in
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
PRO_PRICE_USD = os.getenv("PRO_PRICE_USD", "4.99").strip()
PRO_PRICE_IQD = os.getenv("PRO_PRICE_IQD", "6500").strip()

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
# SpeakUp runs entirely on built-in content (see content.py). There are no
# API keys, no rate limits, and no per-user cost. Practice sentences and
# conversations are all pre-written and translated, so the app works the
# same for one user or a million.
from content import (SENTENCE_BANK, CONVERSATIONS, CONVERSATION_BY_ID,
                     SPRINT_CONVS, SPRINT_CONVS_BIZ, SHADOW_CATEGORIES)

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
            "Hello, nice to meet you.",
            "My name is Sara. What's your name?",
            "Where are you from?",
            "I'm learning English to travel.",
            "It was great talking to you.",
        ],
    },
    {
        "id": "cafe",
        "title": "Ordering at a Café",
        "level": "Beginner",
        "is_premium": False,
        "phrases": [
            "Could I have a coffee, please?",
            "Do you have any tea without sugar?",
            "How much is this sandwich?",
            "Can I pay by card?",
            "Thank you, have a nice day.",
        ],
    },
    {
        "id": "interview",
        "title": "Job Interview Basics",
        "level": "Intermediate",
        "is_premium": True,
        "phrases": [
            "Thank you for inviting me to this interview.",
            "I have three years of experience in this field.",
            "I work well both independently and in a team.",
            "My greatest strength is solving problems quickly.",
            "When can I expect to hear back from you?",
        ],
    },
    {
        "id": "travel",
        "title": "Travel & Airport",
        "level": "Intermediate",
        "is_premium": True,
        "phrases": [
            "Where is the check-in counter for this flight?",
            "I would like a window seat, please.",
            "How long is the layover in Istanbul?",
            "Excuse me, is this the gate for the London flight?",
            "Could you help me find my luggage?",
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
            "Could you clarify what you mean by that?",
            "I think we should postpone this decision.",
            "Let's schedule a follow-up meeting for next week.",
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
    msg["Subject"] = "Reset your SpeakUp password"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "We got a request to reset your SpeakUp password.\n\n"
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
app = FastAPI(title="SpeakUp API")


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
    frontend, then finds or creates a SpeakUp account for that email.

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
    attempts = session.exec(select(Attempt).where(Attempt.created_at >= week_start)).all()
    days_done = session.exec(select(DayCompletion).where(DayCompletion.completed_at >= week_start)).all()

    xp_by_user: dict[int, int] = defaultdict(int)
    for a in attempts:
        xp_by_user[a.user_id] += 10 + (5 if a.score >= 85 else 0)
    for d in days_done:
        xp_by_user[d.user_id] += 100

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


@app.get("/api/lessons")
def list_lessons(user: User = Depends(get_current_user)):
    """Free lessons are always unlocked. Premium lessons need is_premium."""
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
    xp = len(attempts) * 10 + sum(5 for a in attempts if a.score >= 85) + len(days_completed) * 100

    # Daily streak: walk back day by day from today while each day was active.
    today = dt.date.today()
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


@app.post("/api/upgrade")
def upgrade(user: User = Depends(get_current_user),
            session: Session = Depends(get_session)):
    """
    DEMO-MODE ONLY. While no real payment provider is configured, this
    instantly grants Pro so you can test the whole app without a Paddle
    account. The moment PADDLE_* env vars are set (production), this
    shortcut is disabled — real Pro access then comes ONLY from a signed
    payment webhook (see /api/billing/webhook below). This prevents anyone
    from just calling this endpoint directly to get Pro for free.
    """
    if PADDLE_CONFIGURED or ZAINCASH_CONFIGURED or QICARD_CONFIGURED:
        raise HTTPException(403, "Real payments are live — use the Upgrade "
                                 "button to check out.")
    user.is_premium = True
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
        "environment": PADDLE_ENV,
        "price_usd": PRO_PRICE_USD,
        "price_iqd": PRO_PRICE_IQD,
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


@app.post("/api/billing/zaincash/checkout")
def zaincash_checkout(request: Request,
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

    # order_id is OUR tracking id (embeds the user id, see _confirm_and_grant_zaincash).
    # externalReferenceId is a SEPARATE field ZainCash requires to be a UUID —
    # conflating the two caused a 400 Bad Request the first time this was tested.
    order_id = f"speakup-{user.id}-{int(time.time())}"
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
            "amount": {"value": PRO_PRICE_IQD, "currency": "IQD"},
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
    "speakup-{user_id}-{timestamp}"), then asks ZainCash's Inquiry API
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
    user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=30)
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
            user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=30)
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
def qicard_checkout(request: Request,
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

    base = str(request.base_url).rstrip("/")
    resp = requests.post(
        f"{QICARD_BASE_URL}/api/v1/payment",
        headers={"X-Terminal-Id": QICARD_TERMINAL_ID, "Content-Type": "application/json"},
        auth=(QICARD_USERNAME, QICARD_PASSWORD),
        json={
            "requestId": str(uuid.uuid4()),
            "amount": float(PRO_PRICE_IQD),
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
    user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=30)
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
        user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=30)
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
            user.pro_expires_at = dt.datetime.utcnow() + dt.timedelta(days=30)
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
    "Hello, nice to meet you.": "مرحباً، سعيد بلقائك.",
    "My name is Sara. What's your name?": "اسمي سارة. ما اسمك؟",
    "Where are you from?": "من أين أنت؟",
    "I'm learning English to travel.": "أتعلم الإنجليزية من أجل السفر.",
    "It was great talking to you.": "كان من الرائع التحدث معك.",

    "Could I have a coffee, please?": "هل يمكنني الحصول على قهوة، من فضلك؟",
    "Do you have any tea without sugar?": "هل لديكم شاي بدون سكر؟",
    "How much is this sandwich?": "كم سعر هذا الساندويتش؟",
    "Can I pay by card?": "هل يمكنني الدفع بالبطاقة؟",
    "Thank you, have a nice day.": "شكراً لك، أتمنى لك يوماً سعيداً.",

    "Thank you for inviting me to this interview.": "شكراً لدعوتي لهذه المقابلة.",
    "I have three years of experience in this field.": "لدي ثلاث سنوات من الخبرة في هذا المجال.",
    "I work well both independently and in a team.": "أعمل بشكل جيد سواء بمفردي أو ضمن فريق.",
    "My greatest strength is solving problems quickly.": "أكبر نقاط قوتي هي حل المشكلات بسرعة.",
    "When can I expect to hear back from you?": "متى يمكنني أن أتوقع الرد منكم؟",

    "Where is the check-in counter for this flight?": "أين مكتب تسجيل الوصول لهذه الرحلة؟",
    "I would like a window seat, please.": "أرغب بمقعد بجانب النافذة، من فضلك.",
    "How long is the layover in Istanbul?": "كم مدة التوقف في إسطنبول؟",
    "Excuse me, is this the gate for the London flight?": "عفواً، هل هذه بوابة رحلة لندن؟",
    "Could you help me find my luggage?": "هل يمكنك مساعدتي في إيجاد أمتعتي؟",

    "Let's begin by reviewing last quarter's results.": "لنبدأ بمراجعة نتائج الربع الماضي.",
    "I'd like to add one point to the agenda.": "أود إضافة نقطة واحدة إلى جدول الأعمال.",
    "Could you clarify what you mean by that?": "هل يمكنك توضيح ما تقصده بذلك؟",
    "I think we should postpone this decision.": "أعتقد أنه علينا تأجيل هذا القرار.",
    "Let's schedule a follow-up meeting for next week.": "لنحدد موعداً لاجتماع متابعة الأسبوع القادم.",
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
def translate(data: TranslateIn, user: User = Depends(get_current_user)):
    """Look up a baked-in translation. Instant, free, offline."""
    text = data.text.strip()
    ar = _TRANSLATION_LOOKUP.get(text, "")
    return {"translated": ar, "lang": "ar", "found": bool(ar)}


# ---- Scripted conversations (branching, no API) ----
def _conv_public(c: dict, locked: bool) -> dict:
    """Scenario card info. Nodes are only sent when actually opened."""
    return {"id": c["id"], "title": c["title"], "level": c["level"],
            "emoji": c["emoji"], "is_premium": c["is_premium"], "locked": locked,
            "setting": "" if locked else c["setting"],
            "goal": "" if locked else c["goal"]}


@app.get("/api/scenarios")
def list_scenarios(user: User = Depends(get_current_user)):
    out = []
    for c in CONVERSATIONS:
        locked = c["is_premium"] and not user.is_premium
        out.append(_conv_public(c, locked))
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
    # Kept for frontend compatibility. Everything is offline and unlimited.
    return {"ready": True, "used": 0, "limit": 0, "offline": True,
            "languages": SUPPORTED_L1}



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
    print("  SpeakUp — starting up")
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
    total_sprint_convs = sum(len(c) for c in SPRINT_CONVS_BY_SPRINT.values())
    print(f"    conversations      : {len(CONVERSATIONS)} scenarios + {total_sprint_convs} sprint days")
    print("=" * 58)
    print("  Open http://localhost:8000 in Google Chrome")
    print("=" * 58 + "\n")


_startup_banner()
