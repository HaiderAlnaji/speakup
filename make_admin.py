"""
Make any account an admin, without touching .env at all.

Use this if the Admin button won't appear. It writes straight to the database,
so there is nothing to configure and nothing to reload.

    python make_admin.py you7@gmail.com

Then LOG OUT and LOG IN again in the browser.
Run with no email to just list every account:

    python make_admin.py
"""
import sys
from sqlmodel import Session, select
from main import engine, User


def list_users():
    with Session(engine) as s:
        users = s.exec(select(User)).all()
        if not users:
            print("No accounts yet. Register one in the browser first.")
            return
        print(f"\n{len(users)} account(s) in the database:\n")
        for u in users:
            tags = []
            if u.is_admin:
                tags.append("ADMIN")
            if u.is_premium:
                tags.append("PRO")
            print(f"  {u.email:35} {' '.join(tags) if tags else '(free user)'}")
        print("\nTo make one an admin:  python make_admin.py THEIR@EMAIL.com\n")


def make_admin(email: str):
    email = email.strip().lower()
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == email)).first()
        if not user:
            print(f"\nNo account found for '{email}'.")
            print("Register it in the browser first, then run this again.")
            list_users()
            return
        user.is_admin = True
        user.is_premium = True  # so you can test the Sprint straight away
        s.add(user)
        s.commit()
        print(f"\nDone. '{email}' is now ADMIN + PRO.")
        print("Now LOG OUT and LOG IN again in the browser.")
        print("The Admin button will appear next to your email.\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_users()
    else:
        make_admin(sys.argv[1])
