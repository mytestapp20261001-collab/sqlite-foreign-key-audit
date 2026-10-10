import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sqlite_audit_tool", HERE / "tool.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "fixture.sqlite"

    def database(self, invalid=False, rows=1, without_rowid=False):
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO parent VALUES (1)")
            suffix = " WITHOUT ROWID" if without_rowid else ""
            connection.execute("CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))" + suffix)
            connection.executemany("INSERT INTO child VALUES (?, ?)", [(n, 999 if invalid else 1) for n in range(rows)])
            connection.commit()
        finally:
            connection.close()
        return self.db

    def test_pass(self):
        self.assertEqual(tool.audit(self.database())["status"], "pass")

    def test_foreign_key_findings(self):
        answer = tool.audit(self.database(invalid=True))
        self.assertEqual(answer["status"], "findings")
        self.assertEqual(answer["findings"][0]["code"], "foreign_key_violation")
        self.assertNotIn("999", json.dumps(answer))
        self.assertNotIn("child", json.dumps(answer))

    def test_without_rowid(self):
        answer = tool.audit(self.database(invalid=True, without_rowid=True))
        self.assertEqual(answer["summary"]["foreign_key_violations_observed"], 1)

    def test_integrity_failure_no_diagnostics(self):
        self.database()
        # Corrupt only this synthetic fixture's freelist count (SQLite header offset 36).
        raw = bytearray(self.db.read_bytes())
        raw[36:40] = (1).to_bytes(4, "big")
        self.db.write_bytes(raw)
        answer = tool.audit(self.db)
        self.assertEqual(answer["status"], "findings")
        self.assertEqual(answer["findings"][0]["code"], "integrity_check_failed")
        self.assertNotIn("freelist", json.dumps(answer))
        self.assertNotIn("child", json.dumps(answer))

    def test_record_boundary(self):
        self.database(invalid=True, rows=2)
        exact = tool.audit(self.db, max_records=2)
        self.assertFalse(exact["summary"]["foreign_key_results_truncated"])
        limited = tool.audit(self.db, max_records=1)
        self.assertTrue(limited["summary"]["foreign_key_results_truncated"])
        self.assertEqual(limited["summary"]["foreign_key_violations_observed"], 1)

    def test_byte_boundary(self):
        self.database()
        size = self.db.stat().st_size
        self.assertEqual(tool.audit(self.db, max_bytes=size)["status"], "pass")
        self.assertEqual(tool.audit(self.db, max_bytes=size-1)["status"], "error")

    def test_read_only_unchanged_no_sidecars(self):
        self.database()
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        real_connect = sqlite3.connect
        calls = []
        def record(database_uri, **kwargs):
            calls.append((database_uri, kwargs))
            return real_connect(database_uri, **kwargs)
        with patch.object(tool.sqlite3, "connect", record):
            self.assertEqual(tool.audit(self.db)["status"], "pass")
        self.assertIn("mode=ro&immutable=1", calls[0][0])
        self.assertTrue(calls[0][1]["uri"])
        self.assertEqual(before, hashlib.sha256(self.db.read_bytes()).hexdigest())
        self.assertEqual(list(self.root.iterdir()), [self.db])

    def test_refuse_sidecar(self):
        self.database()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.db) + suffix)
            sidecar.touch()
            self.assertEqual(tool.audit(self.db)["status"], "error")
            sidecar.unlink()

    def test_symlink_rejected(self):
        self.database()
        link = self.root / "link.sqlite"
        link.symlink_to(self.db)
        self.assertEqual(tool.audit(link)["status"], "error")

    def test_malformed_and_missing(self):
        self.assertEqual(tool.audit(self.db)["status"], "error")
        self.db.write_bytes(b"not sqlite")
        self.assertEqual(tool.audit(self.db)["status"], "error")
        self.db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
        self.assertEqual(tool.audit(self.db)["status"], "error")

    def test_bounded_work(self):
        self.database(rows=1000)
        self.assertEqual(tool.audit(self.db, max_steps=1)["status"], "error")

    def test_bad_limits(self):
        self.database()
        for kwargs in ({"max_records": 0}, {"max_steps": True}, {"timeout_seconds": float("nan")},
                       {"timeout_seconds": float("inf")}, {"max_bytes": -1}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(tool.audit(self.db, **kwargs)["status"], "error")

    def test_cli_and_generator(self):
        destination = self.root / "examples"
        p = subprocess.run([sys.executable, "-I", str(HERE / "examples/create_examples.py"), str(destination)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for args, expected in (([str(destination / "pass.sqlite")], 0),
                               ([str(destination / "fail.sqlite")], 1),
                               ([str(destination / "missing.sqlite")], 2),
                               ([str(destination / "pass.sqlite"), "--max-bytes", "bad"], 2), ([], 2)):
            with self.subTest(args=args):
                p = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"), *args], capture_output=True, text=True)
                self.assertEqual(p.returncode, expected, p.stderr)
                self.assertEqual(json.loads(p.stdout)["schema_version"], 1)
                self.assertEqual(p.stderr, "")
        again = subprocess.run([sys.executable, "-I", str(HERE / "examples/create_examples.py"), str(destination)], capture_output=True, text=True)
        self.assertNotEqual(again.returncode, 0)

    def test_parent_components_rejected_before_normalization(self):
        self.database()
        other = self.root / "other"; other.mkdir()
        (other / "sub").mkdir()
        (self.root / "link").symlink_to(other / "sub", target_is_directory=True)
        selected = str(self.root) + "/link/../fixture.sqlite"
        self.assertEqual(tool.audit(selected)["status"], "error")
        self.assertEqual(tool.audit(str(other) + "/../fixture.sqlite")["status"], "error")
        self.assertEqual(tool.audit(self.db)["status"], "pass")
        p = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"), selected], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2); self.assertEqual(p.stderr, "")
        self.assertEqual(json.loads(p.stdout)["status"], "error")

    def test_cli_argument_errors_do_not_echo_input(self):
        secret = "PRIVATE_ARGUMENT_VALUE"
        process = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"),
                                  "--unknown=" + secret], capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn(secret, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["errors"][0]["message"], "invalid command arguments")


if __name__ == "__main__":
    unittest.main()
