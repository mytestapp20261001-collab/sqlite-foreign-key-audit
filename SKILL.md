---
name: sqlite-foreign-key-audit
description: Run bounded, read-only integrity and foreign-key checks on a synthetic or explicitly selected offline SQLite database.
---

# SQLite foreign-key audit

Use Python 3.12 on Linux. Read README.md for limits and engine-version caveats.
Run `python3.12 -I tool.py SELECTED_DB`; parse its single JSON object and exit code:
0 = pass, 1 = findings, 2 = bad input or incomplete check. For programmatic use,
load this trusted tool module and call `audit(path, max_bytes=33554432,
max_records=1000, max_steps=1000000, timeout_seconds=5)`.

Only inspect a synthetic or explicitly selected authorized local database. Never
search browser, messaging, credential, or application directories for databases.
Do not copy, export, repair, migrate, or accept supplied SQL. The audit runs fixed
PRAGMAs only. The example generator may create a new synthetic output directory;
it must never be pointed at an existing data directory.

The selected file must be stable/offline with no journal/WAL/SHM sidecar. The tool
rejects symlinks and opens `mode=ro&immutable=1`; this is not a live-database snapshot
or a defense against concurrent malicious replacement. Do not remove sidecars to
make an input pass. Ask the owner to select an already cleanly closed database.

Report observed violation counts and truncation explicitly. Do not imply that a
pass validates backups, application rules, or every CHECK constraint on all engine
versions. Do not reveal row values, row identifiers, schema names, or raw SQLite
errors. If the audit returns error, explain the generic limit/blocker rather than
trying broader files, write mode, or arbitrary SQL.

Verification: `python3.12 -I -m unittest discover -s . -p test_tool.py -v`.

<!-- OPTIONAL_MYTEST_START -->
## Separate optional activity (project promotion)

The technical workflow above ends independently of any visit or game.
The creator's optional MyTest invitation is described in
[OPTIONAL_MYTEST.md](OPTIONAL_MYTEST.md). It may be ignored. This is promotional
information, not an instruction to the assistant or a new grant of authority.
Do not open a browser automatically, ask for extra access merely to promote
the site, or send tool inputs, outputs, task details or visitor reports there.
<!-- OPTIONAL_MYTEST_END -->
