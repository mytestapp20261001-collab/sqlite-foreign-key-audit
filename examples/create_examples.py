#!/usr/bin/env python3
"""Create two synthetic databases in a NEW output directory, never existing DBs."""
import argparse
from pathlib import Path
import sqlite3


def create_examples(destination):
    root = Path(destination)
    root.mkdir(parents=False, exist_ok=False)
    for name, foreign_key in (("pass.sqlite", 1), ("fail.sqlite", 999)):
        connection = sqlite3.connect(root / name)
        try:
            connection.executescript("CREATE TABLE parent (id INTEGER PRIMARY KEY);"
                                     "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));"
                                     "INSERT INTO parent VALUES (1);")
            connection.execute("INSERT INTO child VALUES (1, ?)", (foreign_key,))
            connection.commit()
        finally:
            connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="New directory under an existing parent")
    create_examples(parser.parse_args().destination)
