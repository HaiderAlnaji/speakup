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
import time
import uuid
import datetime as dt
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
from fastapi.responses import FileResponse, Response, RedirectResponse
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
# 1b. CONTENT CONFIG  (everything is offline — no API, no keys, no limits)
# ----------------------------------------------------------------------
# SpeakUp runs entirely on built-in content (see content.py). There are no
# API keys, no rate limits, and no per-user cost. Practice sentences and
# conversations are all pre-written and translated, so the app works the
# same for one user or a million.
from content import (SENTENCE_BANK, CONVERSATIONS, CONVERSATION_BY_ID,
                     SPRINT_CONVS)

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

SPRINT_TOTAL_DAYS = len(SPRINT["days"])
SPRINT_DAY_BY_NUM = {d["day"]: d for d in SPRINT["days"]}




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
    return {"email": user.email, "is_premium": user.is_premium,
            "is_admin": is_admin_user(user)}


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


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not is_admin_user(user):
        raise HTTPException(403, "Admin access only.")
    return user


@app.get("/api/me")
def me(user: User = Depends(get_current_user)):
    return public_user(user)


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


@app.post("/api/practice")
def save_practice(data: PracticeIn, user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    lesson = LESSON_BY_ID.get(data.lesson_id)
    if not lesson:
        raise HTTPException(404, "Lesson not found.")
    if lesson["is_premium"] and not user.is_premium:
        raise HTTPException(403, "This is a premium lesson.")
    score = max(0, min(100, int(data.score)))
    attempt = Attempt(
        user_id=user.id, lesson_id=data.lesson_id,
        phrase_index=data.phrase_index, score=score,
        transcript=data.transcript[:500],
    )
    session.add(attempt)
    session.commit()
    return {"saved": True, "score": score}


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
    if PADDLE_CONFIGURED or ZAINCASH_CONFIGURED:
        raise HTTPException(403, "Real payments are live — use the Upgrade "
                                 "button to check out.")
    user.is_premium = True
    session.add(user)
    session.commit()
    return {"is_premium": True}


@app.get("/api/billing/config")
def billing_config(user: User = Depends(get_current_user)):
    """
    Tells the frontend how to open checkout, and which provider is live.
    Only ever exposes PUBLIC values (safe in the browser) — secret keys
    never leave the server. If both happened to be configured, Paddle wins;
    in practice for SpeakUp it'll be ZainCash.
    """
    provider = "paddle" if PADDLE_CONFIGURED else ("zaincash" if ZAINCASH_CONFIGURED else "none")
    return {
        "configured": provider != "none",
        "provider": provider,
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
        return resp.json().get("data", {}).get("status")
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


@app.get("/api/billing/zaincash/debug")
def zaincash_debug(tx: str = "", user: User = Depends(get_current_user)):
    """
    TEMPORARY debug helper — calls the Inquiry API directly for the CALLING
    user's own last transaction (or an explicit ?tx=<id> override, for
    re-checking a specific past transaction while debugging) and returns the
    raw response so we can see exactly why it isn't being recognized as
    SUCCESS, instead of the silently-swallowed None from zaincash_inquiry().
    Safe to delete once ZainCash integration is verified.
    """
    transaction_id = tx or user.zaincash_transaction_id
    if not transaction_id:
        return {"error": "no zaincash_transaction_id on this user"}
    try:
        token = get_zaincash_token()
    except requests.RequestException as e:
        return {"stage": "token", "error": str(e), "response": getattr(e, "response", None) and e.response.text}
    try:
        resp = requests.get(
            f"{ZAINCASH_BASE_URL}/api/v2/payment-gateway/transaction/inquiry/{transaction_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        return {"stage": "inquiry", "status_code": resp.status_code, "body": resp.text[:2000]}
    except requests.RequestException as e:
        return {"stage": "inquiry", "error": str(e)}


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
# 7b. SPRINT ROUTES — the intensive course
# ----------------------------------------------------------------------
def _sprint_state(user: User, session: Session) -> dict:
    """Works out where the user is in the sprint right now."""
    enr = session.exec(
        select(Enrollment).where(Enrollment.user_id == user.id,
                                 Enrollment.sprint_id == SPRINT["id"])
    ).first()
    if not enr:
        return {"enrolled": False}

    drill_rows = session.exec(
        select(DayCompletion).where(DayCompletion.user_id == user.id,
                                    DayCompletion.sprint_id == SPRINT["id"])
    ).all()
    drill_done = {r.day_number: r.avg_score for r in drill_rows}

    conv_rows = session.exec(
        select(DayConvDone).where(DayConvDone.user_id == user.id,
                                  DayConvDone.sprint_id == SPRINT["id"])
    ).all()
    conv_done = {r.day_number for r in conv_rows}

    # A day is only truly CLEARED once both stages are done: the quick
    # drill, then a real conversation that puts those phrases to use.
    done = {d: score for d, score in drill_done.items() if d in conv_done}

    # How many days have passed since enrolling. Day 1 unlocks immediately.
    elapsed = (dt.datetime.utcnow() - enr.started_at).days
    unlocked_through = min(elapsed + 1, SPRINT_TOTAL_DAYS)

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
        "total_days": SPRINT_TOTAL_DAYS,
        "percent": round(len(done) / SPRINT_TOTAL_DAYS * 100),
        "avg_score": round(sum(scores) / len(scores)) if scores else 0,
        "finished": len(done) == SPRINT_TOTAL_DAYS,
        "pass_score": PASS_SCORE,
    }


@app.get("/api/sprint")
def get_sprint(user: User = Depends(get_current_user),
               session: Session = Depends(get_session)):
    """Sprint overview. Day content is only sent for days that are unlocked."""
    state = _sprint_state(user, session)
    unlocked_through = state.get("unlocked_through", 0) if state["enrolled"] else 0
    drill_set = set(state.get("drill_done_days", []))
    conv_set = set(state.get("conv_done_days", []))

    days = []
    for d in SPRINT["days"]:
        # A day is open if: enrolled, premium, and its turn has arrived.
        open_now = (state["enrolled"] and user.is_premium
                    and d["day"] <= unlocked_through)
        day_conv = SPRINT_CONVS.get(d["day"])
        days.append({
            "day": d["day"],
            "theme": d["theme"],
            "locked": not open_now,
            # Content stays on the server until the day is genuinely unlocked.
            "challenge": d["challenge"] if open_now else "",
            "phrases": d["phrases"] if open_now else [],
            # Just enough for the day card; the full dialogue comes from
            # /api/conversation/sprintday{n} when the learner opens it.
            "conv": ({"setting": day_conv["setting"], "goal": day_conv["goal"]}
                     if open_now and day_conv else None),
            "drill_done": d["day"] in drill_set,
            "conv_done": d["day"] in conv_set,
        })

    return {
        "id": SPRINT["id"],
        "title": SPRINT["title"],
        "promise": SPRINT["promise"],
        "is_premium_user": user.is_premium,
        "days": days,
        "state": state,
    }


@app.post("/api/sprint/enroll")
def enroll(user: User = Depends(get_current_user),
           session: Session = Depends(get_session)):
    if not user.is_premium:
        raise HTTPException(403, "The Sprint is a Pro program.")
    existing = session.exec(
        select(Enrollment).where(Enrollment.user_id == user.id,
                                 Enrollment.sprint_id == SPRINT["id"])
    ).first()
    if existing:
        raise HTTPException(400, "You're already enrolled in the Sprint.")
    session.add(Enrollment(user_id=user.id, sprint_id=SPRINT["id"]))
    session.commit()
    return _sprint_state(user, session)


class DayDoneIn(BaseModel):
    day: int
    avg_score: int


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
    state = _sprint_state(user, session)
    if not state["enrolled"]:
        raise HTTPException(400, "Start the Sprint first.")
    if data.day not in SPRINT_DAY_BY_NUM:
        raise HTTPException(404, "That day doesn't exist.")
    # The core rule: you cannot jump ahead of the calendar.
    if data.day > state["unlocked_through"]:
        raise HTTPException(403, "That day hasn't unlocked yet. Come back tomorrow.")

    score = max(0, min(100, int(data.avg_score)))
    if score < PASS_SCORE:
        raise HTTPException(400, f"You need {PASS_SCORE}% or higher to finish the day.")

    existing = session.exec(
        select(DayCompletion).where(DayCompletion.user_id == user.id,
                                    DayCompletion.sprint_id == SPRINT["id"],
                                    DayCompletion.day_number == data.day)
    ).first()
    if existing:
        # Already done — keep the best score.
        existing.avg_score = max(existing.avg_score, score)
        session.add(existing)
    else:
        session.add(DayCompletion(user_id=user.id, sprint_id=SPRINT["id"],
                                  day_number=data.day, avg_score=score))
    session.commit()
    return _sprint_state(user, session)


class DayNumIn(BaseModel):
    day: int


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
    state = _sprint_state(user, session)
    if not state["enrolled"]:
        raise HTTPException(400, "Start the Sprint first.")
    if data.day not in SPRINT_DAY_BY_NUM:
        raise HTTPException(404, "That day doesn't exist.")
    if data.day not in state.get("drill_done_days", []):
        raise HTTPException(400, "Finish today's phrase drill first.")

    existing = session.exec(
        select(DayConvDone).where(DayConvDone.user_id == user.id,
                                  DayConvDone.sprint_id == SPRINT["id"],
                                  DayConvDone.day_number == data.day)
    ).first()
    if not existing:
        session.add(DayConvDone(user_id=user.id, sprint_id=SPRINT["id"], day_number=data.day))
        session.commit()
    return _sprint_state(user, session)


@app.get("/api/sprint/certificate")
def certificate(user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    state = _sprint_state(user, session)
    if not state.get("finished"):
        raise HTTPException(403, "Finish all 14 days to earn your certificate.")
    return {
        "name": user.email.split("@")[0],
        "title": SPRINT["title"],
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
for _c in CONVERSATIONS:
    for _node in _c["nodes"]:
        _TRANSLATION_LOOKUP[_node["npc"]["en"]] = _node["npc"]["ar"]
        for _r in _node.get("replies", []):
            _TRANSLATION_LOOKUP[_r["en"]] = _r["ar"]
for _day in SPRINT_CONVS.values():
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
        try:
            day_num = int(conv_id[len("sprintday"):])
        except ValueError:
            raise HTTPException(404, "Conversation not found.")
        conv = SPRINT_CONVS.get(day_num)
        if not conv:
            raise HTTPException(404, "Conversation not found.")
        if not user.is_premium:
            raise HTTPException(403, "The Sprint is a Pro program.")
        state = _sprint_state(user, session)
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
        st = _sprint_state(u, session)
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
    TESTING ONLY. Enrolls the admin in the Sprint if needed, then backdates
    the start date so every one of the 14 days is unlocked right now. This
    lets you click through and test all 14 days without waiting 14 days.
    It does not mark any day as *completed* — you still practice each one.
    """
    enr = session.exec(
        select(Enrollment).where(Enrollment.user_id == admin.id,
                                 Enrollment.sprint_id == SPRINT["id"])
    ).first()
    backdate = dt.datetime.utcnow() - dt.timedelta(days=SPRINT_TOTAL_DAYS)
    if enr:
        enr.started_at = backdate
        session.add(enr)
    else:
        session.add(Enrollment(user_id=admin.id, sprint_id=SPRINT["id"], started_at=backdate))
    session.commit()
    return _sprint_state(admin, session)


@app.post("/api/admin/sprint/reset")
def admin_reset_sprint(admin: User = Depends(require_admin),
                       session: Session = Depends(get_session)):
    """TESTING ONLY. Wipes the admin's own Sprint progress to start over."""
    for row in session.exec(
        select(Enrollment).where(Enrollment.user_id == admin.id, Enrollment.sprint_id == SPRINT["id"])
    ).all():
        session.delete(row)
    for row in session.exec(
        select(DayCompletion).where(DayCompletion.user_id == admin.id, DayCompletion.sprint_id == SPRINT["id"])
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
    print(f"  Sprint days          : {SPRINT_TOTAL_DAYS}   Pass score: {PASS_SCORE}%")
    print(f"  Content              : OFFLINE (no API, no keys, no limits)")
    print(f"    practice sentences : {sum(len(v) for v in SENTENCE_BANK.values())} across "
          f"{len(SENTENCE_BANK)} levels")
    print(f"    conversations      : {len(CONVERSATIONS)} scenarios + {len(SPRINT_CONVS)} sprint days")
    print("=" * 58)
    print("  Open http://localhost:8000 in Google Chrome")
    print("=" * 58 + "\n")


_startup_banner()
