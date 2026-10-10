#!/usr/bin/env python3
"""Read-only, bounded SQLite integrity/FK audit without exposing row values."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

TOOL = "sqlite-foreign-key-audit"


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid command arguments")


def result(findings=None, summary=None, error=None):
    findings = findings or []
    return {"schema_version": 1, "tool": TOOL,
            "status": "error" if error else "findings" if findings else "pass",
            "summary": summary or {}, "findings": findings,
            "errors": [{"code": "bad_input", "message": error}] if error else []}


def selected_absolute(path):
    """Reject parent traversal before normalization can hide symlink components."""
    raw = Path(os.fspath(path))
    if ".." in raw.parts:
        raise InputError("Selected paths must not contain parent (..) components")
    return Path(os.path.abspath(raw))


def open_selected(path):
    if not hasattr(os, "O_NOFOLLOW") or not Path("/proc/self/fd").is_dir():
        raise InputError("This tool requires Linux O_NOFOLLOW and /proc/self/fd")
    absolute = selected_absolute(path)
    if not absolute.name:
        raise InputError("Select one SQLite file")
    parent = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.stat(absolute.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise InputError("Sidecar exists; select an offline, cleanly closed standalone database")
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        return fd
    finally:
        os.close(parent)


def _audit(database, max_bytes, max_records, max_steps, timeout_seconds):
    for name, value, upper in (("max_bytes", max_bytes, 268435456),
                               ("max_records", max_records, 100000),
                               ("max_steps", max_steps, 100000000)):
        if type(value) is not int or not 1 <= value <= upper:
            raise InputError(f"{name} must be an integer from 1 to {upper}")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
        raise InputError("timeout_seconds must be finite and greater than 0, at most 60")
    fd = open_selected(database)
    conn = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise InputError("Selected database must be a regular file")
        if before.st_size > max_bytes:
            raise InputError("Database exceeds max_bytes")
        if os.pread(fd, 16, 0) != b"SQLite format 3\x00":
            raise InputError("Selected file does not have a SQLite 3 header")
        # Immutable suppresses journal/SHM writes. The caller must select an offline DB.
        uri = f"file:/proc/self/fd/{fd}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True, timeout=0, isolation_level=None)
        if hasattr(conn, "setconfig") and hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
            conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, min(max_bytes, 16777216))
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1048576)
        started = time.monotonic()
        consumed = 0
        def progress():
            nonlocal consumed
            consumed += 100
            return int(consumed >= max_steps or time.monotonic() - started >= timeout_seconds)
        conn.set_progress_handler(progress, 100)
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-2048")
        findings = []
        integrity = conn.execute(f"PRAGMA integrity_check({max_records})")
        integrity_errors = sum(1 for row in integrity if row != ("ok",))
        if integrity_errors:
            findings.append({"code": "integrity_check_failed", "observed_errors": integrity_errors,
                             "limit_reached": integrity_errors >= max_records})
        violations = 0
        truncated = False
        foreign_keys = conn.execute("PRAGMA foreign_key_check")
        for _ in foreign_keys:
            if violations == max_records:
                truncated = True
                break
            violations += 1
        foreign_keys.close()
        if violations:
            findings.append({"code": "foreign_key_violation", "observed_violations": violations,
                             "truncated": truncated})
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InputError("Database changed during inspection; select an offline database")
        return result(findings, {"database_bytes": before.st_size,
                                "integrity_errors_observed": integrity_errors,
                                "foreign_key_violations_observed": violations,
                                "foreign_key_results_truncated": truncated,
                                "sqlite_version": sqlite3.sqlite_version})
    finally:
        if conn is not None:
            conn.close()
        os.close(fd)


def audit(database, *, max_bytes=33554432, max_records=1000,
          max_steps=1000000, timeout_seconds=5):
    """Audit an explicitly selected, offline local DB; return no data/row identifiers."""
    try:
        return _audit(database, max_bytes, max_records, max_steps, timeout_seconds)
    except InputError as exc:
        return result(error=str(exc))
    except sqlite3.Error:
        # SQLite diagnostic text can contain table names or data; never echo it.
        return result(error="SQLite could not complete the checks (invalid database, schema, or work limit)")
    except (OSError, TypeError, ValueError):
        return result(error="Cannot inspect the selected database safely")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("database", help="Explicitly selected offline SQLite file")
    parser.add_argument("--max-bytes", type=int, default=33554432)
    parser.add_argument("--max-records", type=int, default=1000)
    parser.add_argument("--max-steps", type=int, default=1000000)
    parser.add_argument("--timeout-seconds", type=float, default=5)
    try:
        args = parser.parse_args(argv)
        outcome = audit(args.database, max_bytes=args.max_bytes, max_records=args.max_records,
                        max_steps=args.max_steps, timeout_seconds=args.timeout_seconds)
    except InputError as exc:
        outcome = result(error=str(exc))
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=True))
    return {"pass": 0, "findings": 1, "error": 2}[outcome["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
