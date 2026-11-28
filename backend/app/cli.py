"""Command line tools: `magma <command>` (or `python -m app.cli <command>`).

magma migrate                      apply database migrations
magma demo-data --seed 42          fill the catalogue with generated demo data
magma db-copy --source URL --target URL [--replace]
                                   copy all data, e.g. SQLite -> PostgreSQL
magma rotate-secret --old KEY      re-encrypt the TOTP seeds and the SSO client secret after
                                   SECRET_KEY was changed
magma reset-password [USER]        set a new password for a local account (default: ADMIN_USER),
                                   unlock it and sign it out; asks for the password, or
                                   --from-env takes ADMIN_PASSWORD; --disable-totp also turns
                                   off two-factor login; --enable also re-enables an account
                                   that an admin disabled
"""

import argparse
import logging
import sys

from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db import make_engine


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(
        prog="magma", description="Vulcan UCF command line tools (MaGMa use case management)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply database migrations and seed an empty database")
    demo = sub.add_parser("demo-data", help="replace the data with generated demo data")
    demo.add_argument("--seed", type=int, default=42)
    cp = sub.add_parser("db-copy", help="copy all data to another database")
    cp.add_argument("--source", help="source database URL (default: DATABASE_URL)")
    cp.add_argument("--target", required=True, help="target database URL")
    cp.add_argument("--replace", action="store_true", help="delete existing data in the target")
    rot = sub.add_parser(
        "rotate-secret", help="re-encrypt stored secrets with the current SECRET_KEY"
    )
    rot.add_argument("--old", required=True, help="the previous SECRET_KEY")
    rp = sub.add_parser(
        "reset-password", help="set a new password for a local account and unlock it"
    )
    rp.add_argument("username", nargs="?", help="default: ADMIN_USER")
    rp.add_argument("--from-env", action="store_true", help="use ADMIN_PASSWORD instead of asking")
    rp.add_argument("--disable-totp", action="store_true", help="also turn off two-factor login")
    rp.add_argument("--enable", action="store_true", help="also re-enable a disabled account")
    args = p.parse_args(argv)

    settings = get_settings()
    if args.cmd == "db-copy":
        from app.dbcopy import CopyError, copy_database

        try:
            res = copy_database(args.source or settings.database_url, args.target, args.replace)
        except CopyError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        for name, n in res.rows.items():
            print(f"{name:28} {n:>8}")
        print(f"{'total':28} {res.total:>8}")
        return 0

    if args.cmd == "reset-password":
        return reset_password(settings, args)

    if args.cmd == "rotate-secret":
        from app import sso
        from app.config import check_secret_key
        from app.totp import reencrypt_all

        check_secret_key(settings)
        engine = make_engine(settings.database_url, settings)
        with sessionmaker(bind=engine)() as db:
            done, failed = reencrypt_all(db, args.old, settings.secret_key)
            sso_done = sso.reencrypt(db, args.old, settings.secret_key)
            db.commit()
        engine.dispose()
        print(f"re-encrypted {done} TOTP secret(s)")
        if sso_done:
            print("re-encrypted the SSO client secret")
        if failed:
            print(
                f"error: {len(failed)} could not be decrypted with --old: {', '.join(failed)}",
                file=sys.stderr,
            )
        if sso_done is None:
            print("error: the SSO client secret could not be decrypted with --old", file=sys.stderr)
        return 1 if failed or sso_done is None else 0

    from app.startup import initialize

    engine = make_engine(settings.database_url, settings)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    initialize(engine, factory, settings)
    if args.cmd == "demo-data":
        from app.demo import apply_demo_data

        with factory() as db:
            print(
                apply_demo_data(db, args.seed, default_interval=settings.default_verification_days)
            )
    engine.dispose()
    return 0


def _ask_password() -> str:
    import getpass

    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat it: "):
        raise ValueError("the passwords do not match")
    return first


def reset_password(settings, args) -> int:
    """Recovery when nobody can sign in: ADMIN_PASSWORD only sets the password of the first admin
    on the very first start, so changing it in .env later has no effect."""
    from sqlalchemy import delete, select

    from app import audit
    from app.api.auth import clear_totp
    from app.models import AuthSource, User, UserSession
    from app.security import hash_password

    username = args.username or settings.admin_user
    try:
        if args.from_env:
            if not settings.admin_password:
                raise ValueError("ADMIN_PASSWORD is not set")
            password = settings.admin_password
        else:
            password = _ask_password()
        if len(password) < settings.min_password_length:
            raise ValueError(
                f"the password must be at least {settings.min_password_length} characters"
            )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    engine = make_engine(settings.database_url, settings)
    try:
        with sessionmaker(bind=engine)() as db:
            user = db.scalar(select(User).where(User.username == username))
            if user is None:
                names = ", ".join(
                    db.scalars(select(User.username).where(User.auth_source == AuthSource.local))
                )
                print(
                    f"error: no user '{username}'. Local users: {names or 'none'}", file=sys.stderr
                )
                return 1
            if user.auth_source != AuthSource.local:
                print(
                    f"error: '{username}' signs in with {user.auth_source.value}, not a password",
                    file=sys.stderr,
                )
                return 1
            user.password_hash = hash_password(password)
            user.failed_logins = 0
            user.locked_until = None
            # a disabled account stays disabled unless asked: someone switched it off on purpose
            if args.enable:
                user.active = True
            if args.disable_totp:
                clear_totp(user)
            db.execute(delete(UserSession).where(UserSession.user_id == user.id))
            audit.record(
                db,
                None,
                "password_reset_cli",
                "user",
                user.username,
                {"totp_disabled": bool(args.disable_totp), "enabled": bool(args.enable)},
            )
            db.commit()
            totp_note = " Two-factor login is still on." if user.totp_enabled else ""
            print(f"Password of '{username}' was reset; the account is unlocked.{totp_note}")
            if not user.active:
                print(
                    f"'{username}' is still disabled and cannot sign in. Run the command again "
                    "with --enable to switch the account back on."
                )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
