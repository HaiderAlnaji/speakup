# SpeakUp — English speaking practice

A working full-stack app whose headline product is **The 14-Day Speaking Sprint**:
an intensive, time-boxed course where exactly **one day unlocks every 24 hours**,
you must **score 70% or higher** to clear a day, you build a **streak**, and you
finish with a **certificate**.

- **Backend:** FastAPI (Python) — accounts, security, lessons, the Sprint.
- **Frontend:** one HTML page, served by the backend. No build step.
- **Speech:** the browser's built-in speech engine — free, no API key.
- **Tests:** 44 automated checks (`smoke_test.py` + `sprint_test.py`).

---

## Why the Sprint is the competitive advantage

Almost every competitor sells the same thing: **unlimited lessons, available
forever, with no urgency.** That sounds generous, but it's exactly why people
quit — nothing is ever due, so nothing ever gets done.

The Sprint inverts that on purpose:

| Everyone else | The Sprint |
|---|---|
| All content, all at once | **One day unlocks per day.** You cannot binge it. |
| Study "whenever" | The clock runs from the moment you enroll. |
| Passive tapping and matching | A **speaking challenge** out loud, every day. |
| Progress bars you can ignore | A **streak** you can visibly break. |
| Finish = nothing | Finish = a **certificate** worth sharing. |
| Endless, so cancel any time | **14 days** — a promise with an end date. |

This is enforced **on the server**, not just hidden in the interface. Day 8's
content is genuinely not sent to the browser until day 8 arrives. A user can't
open developer tools and skip ahead — I tested exactly that (`sprint_test.py`
proves a jump to day 5 returns `403`).

Why this makes money: a 14-day program with a deadline is a **reason to pay
today** and a **reason to come back tomorrow**. "Unlimited lessons" is a reason
to pay later — i.e. never.

**One honest caution:** the deadline pressure *is* the product, and pressure isn't
for everyone. Some users will miss day 3 and quit for good. Watch your completion
rate. If people drop off badly, consider one "repair" day they can spend to fix a
broken streak — but don't add so much forgiveness that the urgency dies. That
tension is a real business decision, not a bug to code away.

---

## 1. Run it on your MacBook (paste one line at a time)

```
cd english-app
```
```
python3 -m venv .venv
```
```
source .venv/bin/activate
```
```
pip install -r requirements.txt
```
```
uvicorn main:app --reload
```

Open **http://localhost:8000** in **Google Chrome** (Chrome handles the mic most
reliably; Safari works too). Click **Allow** when it asks for the microphone.

**Try the Sprint:**
1. Create an account.
2. Click **Start the Sprint** on the blue banner → you'll hit the paywall.
3. Click **Upgrade to Pro** (demo mode unlocks instantly).
4. Click **Start Day 1 now**.
5. Read the challenge, tap **🔊 Listen**, then tap the **mic** and say the phrase.
6. Clear all 5 phrases with a 70%+ average → Day 1 turns green, streak = 1.
7. Notice **Day 2 is still locked.** It opens tomorrow. That's the whole product.

To stop: **Ctrl + C**. To run it again later, just repeat the
`source .venv/bin/activate` and `uvicorn main:app --reload` lines.

### Run the tests
```
python smoke_test.py
```
```
python sprint_test.py
```
```
python admin_test.py
```
55 checks total. `sprint_test.py` fakes the passage of time, so it verifies the
day-unlocking rules without waiting two weeks.

---

## 1b. Become admin, and unlock all 14 days for testing

You don't need to wait 14 real days to see every Sprint day. Do this once:

1. Copy `.env.example` to `.env`:
   ```
   cp .env.example .env
   ```
2. Open `.env` and set `ADMIN_EMAIL` to the email you'll sign up with, e.g.
   `ADMIN_EMAIL=haider@example.com`.
3. Restart the server (`Ctrl+C`, then `uvicorn main:app --reload` again).
4. Register or log in with that exact email. You're now an admin — an **Admin**
   button appears next to your name in the top bar.
5. Open **Admin** → **Grant Pro** to yourself in the Users table (the Sprint
   requires Pro) → click **Unlock all days**.
6. Go back to the Sprint. All 14 days are open. You still have to **speak and
   pass each one** — this only removes the daily wait, so you can genuinely
   test every day's content in one sitting.

The admin panel also lets you grant/remove Pro for any user, and reset your own
Sprint progress to re-test the "Day 1" experience from scratch.

**Admin security (important):** `ADMIN_EMAIL` in `.env` is the *single source of
truth* — the only way to be an admin. On **every request**, the server checks
your email against that list: if it matches you're admin, if it doesn't you are
actively made non-admin, no matter what's stored in the database. That means:

- Nobody can promote themselves — there's no "first user = admin" backdoor.
- A leftover admin flag in the database (e.g. from earlier testing) **cannot**
  keep granting access — it's ignored and cleaned up automatically.
- To add a second admin, list both emails comma-separated:
  `ADMIN_EMAIL=you@x.com,partner@x.com`.
- If an old test account still shows as admin in the database, run
  `python make_admin.py --clean` to strip stale flags (purely cosmetic — the
  server already ignores them for access decisions).

---

## 2. What each file does

| File | What it is |
|------|-----------|
| `main.py` | The backend, in numbered commented sections. |
| `content.py` | All practice content — sentences, conversations, translations. |
| `static/index.html` | The entire frontend (HTML + CSS + JavaScript). |
| `requirements.txt` | Python packages. |
| `render.yaml` | Deploy settings — Render reads this automatically, including the Postgres database. |
| `.env.example` | Template — copy to `.env`. `SECRET_KEY`, `ADMIN_EMAIL` for local dev; `DATABASE_URL` and `PADDLE_*` for production. |
| `smoke_test.py`, `admin_test.py`, `sprint_test.py`, `content_test.py`, `streak_test.py`, `stale_token_test.py`, `billing_test.py`, `migration_test.py` | Automated tests — run any of them with `python <name>.py`. |
| `make_admin.py` | Inspect accounts and clean up stale admin flags — see section 1b. |
| `app.db` | The local SQLite database (dev only), created on first run. Ignored by git. |

---

## 3. Timed practice sessions (drill stage) — how it actually works

Each day's drill is no longer 5 fixed sentences. It's a **timed session**:

1. Pick a **level** (Beginner/Intermediate/Advanced) and a **length**
   (10/20/30/60/90 minutes) before starting.
2. Sentences are **generated by AI in batches of ~20**, tied to that day's
   theme, and the app quietly fetches the next batch before you run out —
   so a 60-minute session never repeats and never runs dry.
3. Every sentence has a **🌐 Translate** button (uses your chosen language,
   cached so repeats cost nothing).
4. When time's up (or you tap "Finish session now"), your average score
   is submitted — 70%+ passes — and you're dropped straight into that
   day's conversation.

**Why not just write 1000 sentences per level?** A fixed list that big is
still finite and still repeats eventually — and 3 levels × 1000 lines is a
huge, unmaintainable file for something an AI generates better on the fly.
Generation gives genuinely unlimited, always-fresh content instead of a big
static list pretending to be unlimited.

**"Drill any topic"** on the dashboard now launches the exact same timed
session — type any topic, pick a level, and go.

---

## 3b. Edit the Sprint content

Each Sprint day now has **two stages**, both required to clear the day:

1. **Drill** — repeat 5 fixed phrases, score 70%+ (unchanged from before).
2. **Conversation** — immediately after, a real CLT conversation that puts
   those same phrases to use. AI-powered, same engine as "Talk to someone."

In `main.py`, find `SPRINT = {`. Each day now looks like this:

```python
{"day": 3, "theme": "Everyday Small Talk",
 "challenge": "Talk about today's weather for 20 seconds.",
 "phrases": ["The weather is really nice today, isn't it?",
             "Did you have a good weekend?"],
 "conv": {"ai_role": "Tom, a coworker you bump into in the hallway",
          "setting": "Monday morning, by the coffee machine.",
          "task": "Make small talk about the weekend, then say goodbye naturally.",
          "goals": ["Ask about the weekend", "End the chat politely"],
          "useful": ["Did you have a good weekend?", "Anyway, I should get going."]}},
```

Leave out `"conv"` on a day and it falls back to drill-only for that day (older
behavior). Change `PASS_SCORE = 70` to make the drill easier or harder.

**Why two stages:** the drill builds the raw phrases; the conversation is where
CLT actually happens — using them to reach a real goal with someone who reacts
unpredictably. Drilling alone was never going to teach communication by itself.

---

## 4. Publish it to the internet (Render — free to start)

Render gives you **HTTPS automatically**, which you need for the microphone to
work at all in public. Browsers block mic access on non-HTTPS pages.

### Step 1 — Put the code on GitHub
Create a **new empty repo** on github.com (call it `speakup`). Then, one line at a time:
```
cd english-app
```
```
git init
```
```
git add .
```
```
git commit -m "SpeakUp: 14-Day Speaking Sprint"
```
```
git branch -M main
```
```
git remote add origin https://github.com/YOUR-USERNAME/speakup.git
```
```
git push -u origin main
```
`.gitignore` already keeps your database and secrets out of the repo.

### Step 2 — Deploy on Render
1. Go to **render.com** → sign up with your GitHub account.
2. Click **New +** → **Blueprint** (not "Web Service" — Blueprint reads
   `render.yaml`, which now also provisions your Postgres database automatically).
3. Pick your `speakup` repo → **Connect**. Render shows you the web service
   AND a `speakup-db` Postgres database it's about to create together.
4. Click **Apply**. Wait ~3 minutes.
5. Add your `ADMIN_EMAIL` in the web service's **Environment** tab, then
   **Manual Deploy** to restart with it applied.

You get a live URL like `https://speakup.onrender.com` — live, on HTTPS, with
a real mic, and a **real Postgres database already connected** (verified: I
tested this exact setup against a genuine Postgres server before writing
this, not just in theory).

### ⚠️ Two things about the free plan you must know
- **The web service sleeps.** After ~15 minutes with no traffic it shuts down
  and the next visitor waits ~30 seconds for it to wake. Fine for testing,
  bad for paying customers. The paid web service plan (~$7/month) doesn't sleep.
- **The free Postgres database expires after 30 days**, with a 14-day grace
  period to upgrade before Render deletes it (and your data) permanently.
  This is a genuine limit, not a bug — **mark your calendar**. Before day 30,
  go to your database in Render → upgrade to a paid instance (starts around
  $6-7/month). Do this before launch if you'll have real paying users; the
  free tier is for building and testing only.

### Step 3 — Your own domain (optional)
Buy one (Namecheap or Cloudflare, ~$10/year). In Render → **Settings** →
**Custom Domain**, add it and copy the DNS record into your registrar. HTTPS is
issued automatically.

**Alternatives:** **Railway** (railway.app) and **Fly.io** work the same way and
are equally beginner-friendly.

---

## 5. The money part — real payments, and how you actually get paid

**Important if your business is based in Iraq:** Paddle, Stripe, Lemon
Squeezy, and Dodo Payments all refuse to onboard sellers registered in Iraq
(it's on each of their unsupported-country lists — a banking/compliance
restriction on their end, not something you can work around at signup). The
route that actually works is **ZainCash**, Iraq's own mobile-wallet payment
gateway, licensed by the Central Bank of Iraq. If your business is based
somewhere Paddle *does* support, use the Paddle path below instead — the
app supports both, and picks whichever one has credentials set.

### ZainCash (Iraq-based businesses)
ZainCash settles in **Iraqi Dinar (IQD) only** — customers pay via their
ZainCash wallet (phone number + one-time code), no card involved. The app
shows a USD price for reference, but the real charge is in IQD.

1. **Register your business**: https://zaincash.iq/business/business-wallet-registration
   — after approval you get a `client_id` and `client_secret`, first for a
   test (UAT) environment, then live credentials once onboarding finishes.
2. **Add env vars** in Render (Environment tab):
   ```
   ZAINCASH_CLIENT_ID=...
   ZAINCASH_CLIENT_SECRET=...
   ZAINCASH_ENV=test            (switch to "production" when ready to go live)
   PRO_PRICE_USD=4.99            (shown to users for reference only)
   PRO_PRICE_IQD=6500             (what actually gets charged; ~1,300 IQD = $1)
   ```
3. **Test with ZainCash's UAT credentials first** (see their docs at
   docs.zaincash.iq for test wallet numbers/OTPs) before flipping
   `ZAINCASH_ENV=production`.
4. **How it works in this codebase**: `POST /api/upgrade` is demo-mode
   only — with no ZainCash (or Paddle) credentials set, it instantly grants
   Pro so you can test everything locally for free. The moment real
   credentials are set, that shortcut disables itself. `/api/billing/zaincash/checkout`
   creates a transaction and sends the customer to ZainCash's page; after
   they pay, `/api/billing/zaincash/callback` confirms the result by calling
   ZainCash's Transaction Inquiry API directly (never trusting the redirect
   URL alone, since that could be forged) before granting Pro. Each payment
   buys 30 days of Pro (`pro_expires_at`), since ZainCash charges one-time
   transactions rather than running recurring subscriptions the way Paddle
   does.

### Paddle (for businesses based somewhere Paddle supports)
Paddle is a "Merchant of Record" — it handles card charging, sales tax, and
compliance for you, and can pay out via Payoneer, wire transfer, or other
methods depending on your country. Check
paddle.com/help/start/intro-to-paddle/which-countries-are-supported-by-paddle
first to confirm your business's country is eligible.

1. **Sign up at paddle.com** (free to start; Paddle takes a percentage per
   sale, no monthly fee).
2. **Create your product & price**: Catalog → New Product → "SpeakUp Pro" →
   add a recurring price, $4.99/month.
3. **Get your keys**: Developer Tools → Authentication →
   - `PADDLE_API_KEY` (secret, server-side only)
   - `PADDLE_CLIENT_TOKEN` (public — safe in the browser)
4. **Set up the webhook**: Developer Tools → Notifications → add endpoint
   `https://YOUR-SITE.onrender.com/api/billing/webhook`, subscribe to
   `subscription.created`, `subscription.activated`, `subscription.canceled`,
   `subscription.paused`, `subscription.past_due`. Copy the signing secret
   as `PADDLE_WEBHOOK_SECRET`.
5. **Add all five env vars** in Render (Environment tab):
   ```
   PADDLE_API_KEY=...
   PADDLE_WEBHOOK_SECRET=...
   PADDLE_CLIENT_TOKEN=...
   PADDLE_PRICE_ID=pri_...        (from your product's price page)
   PADDLE_ENV=sandbox              (switch to "production" when ready to go live)
   ```
6. **Test in sandbox first.** Paddle gives you a full sandbox environment
   with fake card numbers — use it before flipping `PADDLE_ENV=production`.
7. **Set up your payout**: in Paddle, go to Payout Settings and choose
   whichever payout method it offers for your country.

### The one rule
Only a verified payment (ZainCash's Inquiry API result, or Paddle's signed
webhook) may ever set `is_premium = True`. Never trust the browser to tell
you someone paid — that's exactly what `billing_test.py` exists to keep
true for the Paddle path.

---

## 5b. Automatic schema migrations (self-healing database)

The app now **automatically adds missing columns to your database on every
startup**, without touching existing data. This matters because SQLModel's
`create_all()` only creates tables that don't exist yet — it does NOT add new
columns to a table that already exists. Without this, updating the app after
adding a new field (like the Paddle subscription columns) would crash every
request that touches that table with `no such column: ...`.

You'll see it happen in the startup banner:
```
🔧 Migrated 'user': added column(s) paddle_customer_id, paddle_subscription_id, subscription_status
```

This only ever **adds** columns — it never renames, drops, or changes a
column's type. That covers every schema change this app makes in practice
(new fields), and it's the one kind of change that's always safe to automate
because existing data is never touched. If a future change needs something
more (renaming a column, changing its type), that still needs a real,
hand-written migration — the auto-migrator will print a clear warning rather
than guess.

Tested in `migration_test.py` (12 checks): an old-schema database is healed
without data loss (existing users, passwords, and premium status all
survive), the migration is idempotent (running it twice is a no-op the
second time), and a login that would have crashed before now succeeds.

---

## 6. Security — what's built in, and what to do before launch

**Honest statement first: no app is 100% "unhackable."** Anyone promising that is
selling something. The goal is layered defense that makes attacks impractical.
What's actually in place:

- Passwords **hashed with bcrypt** — never stored as readable text.
- Logins use signed **JWT tokens**.
- **Rate limiting** on login/registration slows password-guessing bots.
- **No SQL injection** — all queries are parameterized via SQLModel.
- **Input validation** on email format and password length.
- **Security headers** (anti-clickjacking, no MIME sniffing).
- Login returns the **same error** for a wrong email and a wrong password, so
  attackers can't discover which emails have accounts.
- **Content is gated on the server.** Locked lessons and future Sprint days are
  never sent to the browser — "view source" reveals nothing.

**Before real users:**
- [ ] Strong `SECRET_KEY` from an env var (`render.yaml` generates one for you).
      Locally: `python -c "import secrets; print(secrets.token_hex(32))"`. Never commit `.env`.
- [ ] **HTTPS** — Render gives it to you, and the mic requires it anyway.
- [ ] Move to **PostgreSQL** (see §4) so data survives.
- [ ] Add **email verification** and **password reset**.
- [ ] Never use `--reload` in production.
- [ ] Put **Cloudflare** in front for DDoS and bot filtering.
- [ ] Keep packages patched: `pip list --outdated`.
- [ ] Back up the database regularly.

---

## 7. Future: the iOS app

**The backend you have is already the iOS backend.** An app is just a different
frontend calling the same `/api/...` endpoints.

- Build it in **React Native / Expo** — the stack you already use.
- Use **RevenueCat** for subscriptions, not Stripe. Apple requires in-app purchase
  for digital goods and takes 15–30%.
- Point the app at your Render URL. Sprint logic, streaks, day unlocking, and the
  certificate all work unchanged.

The Sprint is a particularly good fit for a phone: daily unlocking is exactly what
push notifications are for. *"Day 6 is open. Your streak is 5."*

---

## 7c. Daily streak (the habit driver)

The dashboard shows a **daily practice streak** — the number of consecutive
days the learner has practised, counting back from today. It's computed live
from their attempt history (no extra database table), and it's the single most
effective feature for bringing people back every day, which is what turns free
users into paying ones.

- The streak stays "alive" if they practised **today or yesterday**, so it
  doesn't reset the instant midnight passes before they open the app.
- Two or more days without practice resets it to zero.
- The banner also tracks their **longest streak** as a personal best to beat.
- It only appears once they've practised at least once (no empty "0-day" nag).

Tested in `streak_test.py` (10 checks covering consecutive days, gaps, the
yesterday grace window, and reset behaviour).

---

## 7d. The Pro feature set

Five things now genuinely separate Pro from free, beyond the Sprint itself:

1. **Streaks** — daily practice streak with a "don't break the chain" banner.
2. **Timed practice sessions** ("Drill any topic" + the Sprint's drill stage) —
   Pro-only; free users get fixed warm-up lessons and 2 free conversations.
3. **A 10-conversation library** (2 free, 8 Pro) spanning cafés, doctors,
   landlords, job interviews, presentations, and salary negotiation.
4. **Progress graph** (`/api/progress/history`, Pro-gated) — daily average
   scores over the last 14 active days, with automatic trend detection
   (improving / declining / steady). Free users see a locked teaser.
5. **Pronunciation Focus** — after each attempt, Pro users see exactly which
   *words* were unclear (highlighted in red) instead of just one overall
   score, with a "🎯 Focus on: ___" tip. Free users still get the score.

The Sprint completion certificate is also now surfaced with a bold banner at
the very top of the dashboard the moment it's earned, not buried in a
sub-page.

All of this is tested in `streak_test.py` (17 checks, including both
"improving" and "declining" trend detection) and `content_test.py` (the
conversation library).

---

## 8. How the content works (100% offline — no API, no keys, no limits)

SpeakUp runs entirely on built-in content. There is **no AI API, no API key,
no rate limit, and no per-user cost.** It works exactly the same for one user
or a million, and it never shows "try again shortly."

Everything lives in **`content.py`**:

### Practice sentences (the drills)
`SENTENCE_BANK` holds sentences for each level (Beginner / Intermediate /
Advanced), each with its Arabic translation baked in. A timed session pulls a
shuffled batch and skips ones already seen. The bank is **large but finite** —
to add variety, just add more `{"en": "...", "ar": "..."}` lines. The app
randomises order, so more sentences = more variety per session.

### Conversations (scripted branching dialogues)
`CONVERSATIONS` (standalone scenarios) and `SPRINT_CONVS` (one per Sprint day)
are **branching dialogue trees**. The character says a line; the learner picks
(or says out loud) one of several replies; each reply leads to the next line.
It's fully deterministic — same choices, same path — so it always works with
zero network calls.

To add or edit a conversation, add nodes with the `_n(...)` helper. Each node
is one character line plus the replies the learner can choose, and each reply
points to the next node's id via `goto`. There's a test
(`content_test.py`) that checks every reply leads to a real node, so you can't
accidentally create a broken/dead-end dialogue.

### Translations
Every sentence and every dialogue line carries its Arabic translation in
`content.py`, so the 🌐 buttons resolve **instantly and offline**. To add
another language, add more keys alongside `"ar"`; missing translations simply
fall back to English.

### Speech scoring
Still uses the browser's built-in speech recognition (free, on-device in
Chrome). No change, no server involved.

### The honest trade-off
Going fully offline means content is **finite** — a big bank, but not the
"infinite" an AI generates. In exchange you get zero cost, zero rate limits,
zero setup, and it never breaks. For a launchable app that reliably satisfies
users, that reliability is usually the better deal. You can keep expanding the
bank in `content.py` over time — it's just data.

### Testing it
```
python content_test.py
```
26 checks: the bank, translations, every conversation tree (no dead links),
premium gating, and that `main.py` imports no `httpx` and has no API-key
config left — i.e. genuinely offline.
