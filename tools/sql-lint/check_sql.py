#!/usr/bin/env python3
"""Checks Sigyll's Flyway SQL against its style rules (see dist/AlloyDB/README.md).

  1. SQL keywords and type names in DDL are UPPERCASE.
  2. Unquoted identifiers are lowercase. Quoted identifiers ("CaCertificates") are left alone,
     and index methods after USING (btree, gin, ...) count as identifiers, so they are lowercase.
  3. Every table created, and every column created or added, has a COMMENT ON TABLE /
     COMMENT ON COLUMN somewhere in the checked file set.

DML (INSERT, UPDATE, DELETE, SELECT), string literals, comments and dollar-quoted bodies
(DO blocks, functions) are not checked.

Usage: check_sql.py [FILE_OR_DIR ...]   (default: dist/AlloyDB)
Exit code 1 when anything fails.
"""
import re
import sys
from pathlib import Path

KEYWORDS = {
    # DDL
    "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "UNIQUE", "ADD", "COLUMN", "CONSTRAINT", "PRIMARY",
    "KEY", "FOREIGN", "REFERENCES", "ON", "DELETE", "UPDATE", "CASCADE", "RESTRICT", "SET", "NULL",
    "NOT", "DEFAULT", "IF", "EXISTS", "COMMENT", "IS", "GENERATED", "BY", "AS", "IDENTITY", "ALWAYS",
    "RENAME", "TO", "SEQUENCE", "SCHEMA", "VIEW", "MATERIALIZED", "FUNCTION", "PROCEDURE", "TRIGGER",
    "TYPE", "CHECK", "WITH", "WITHOUT", "TIME", "ZONE", "INCLUDE", "WHERE", "AND", "OR", "USING",
    "GRANT", "REVOKE", "ALL", "PRIVILEGES", "USAGE", "SELECT", "INSERT", "TRUNCATE", "EXECUTE",
    "ROUTINES", "TABLES", "SEQUENCES", "IN", "FOR", "EACH", "ROW", "BEFORE", "AFTER", "OF", "NO",
    "ACTION", "DEFERRABLE", "INITIALLY", "DEFERRED", "IMMEDIATE", "CONCURRENTLY", "ONLY", "OWNER",
    "COLLATE", "TEMP", "TEMPORARY", "LIKE", "INHERITS", "PARTITION", "RANGE", "LIST", "HASH",
    "VALUES", "FROM", "INCREMENT", "START", "MINVALUE", "MAXVALUE", "CACHE", "CYCLE", "OWNED",
    "NONE", "DATA", "REPLACE", "RETURNS", "LANGUAGE", "IMMUTABLE", "STABLE", "VOLATILE", "STRICT",
    "TRUE", "FALSE", "CURRENT_TIMESTAMP", "NOW", "ENABLE", "DISABLE", "VALID", "VALIDATE",
    # types
    "INTEGER", "INT", "INT2", "INT4", "INT8", "BIGINT", "SMALLINT", "SERIAL", "BIGSERIAL", "TEXT",
    "BOOLEAN", "BOOL", "BYTEA", "JSON", "JSONB", "UUID", "NUMERIC", "DECIMAL", "REAL", "DOUBLE",
    "PRECISION", "CHARACTER", "VARYING", "VARCHAR", "CHAR", "TIMESTAMP", "TIMESTAMPTZ", "DATE",
    "INTERVAL", "INET", "CIDR", "XML", "ARRAY",
}
DDL_STARTS = {"CREATE", "ALTER", "DROP", "COMMENT", "GRANT", "REVOKE"}

TOKEN = re.compile(r'"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*|\S')


def strip_noise(sql: str) -> str:
    """Blanks out comments, string literals and dollar-quoted bodies, keeping line numbers."""
    out, i, n = [], 0, len(sql)
    while i < n:
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", sql[i:j])); i = j
        elif sql[i] == "'":
            j = i + 1
            while j < n and not (sql[j] == "'" and not sql.startswith("''", j)):
                j += 2 if sql.startswith("''", j) else 1
            j = min(j + 1, n)
            out.append("''" + re.sub(r"[^\n]", " ", sql[i + 2:j]) if j - i >= 2 else sql[i:j]); i = j
        elif sql[i] == "$" and (m := re.match(r"\$[A-Za-z_]*\$", sql[i:])):
            tag = m.group(0)
            j = sql.find(tag, i + len(tag))
            j = n if j < 0 else j + len(tag)
            out.append(tag + re.sub(r"[^\n]", " ", sql[i + len(tag):j - len(tag)]) + tag); i = j
        else:
            out.append(sql[i]); i += 1
    return "".join(out)


def statements(text: str):
    """Yields (line, statement) split on semicolons of noise-stripped text."""
    line, start = 1, 0
    for i, ch in enumerate(text):
        if ch == ";":
            stmt = text[start:i]
            first = start + (len(stmt) - len(stmt.lstrip()))
            yield line + text[start:first].count("\n"), stmt.strip()
            line += text[start:i + 1].count("\n")
            start = i + 1
    rest = text[start:].strip()
    if rest:
        yield line + text[start:].count("\n") - text[start:].lstrip().count("\n"), rest


def unquote(name: str) -> str:
    return name[1:-1].replace('""', '"') if name.startswith('"') else name.lower()


def check(files: list[Path]) -> list[str]:
    errors = []
    created_tables, created_columns = [], []
    table_comments, column_comments = set(), set()

    for path in files:
        text = strip_noise(path.read_text(encoding="utf-8-sig"))
        for line, stmt in statements(text):
            tokens = TOKEN.findall(stmt)
            if not tokens or tokens[0].upper() not in DDL_STARTS:
                continue
            words = [t for t in tokens if not t.startswith('"') and re.match(r"[A-Za-z_]", t)]
            prev = None
            for t in tokens:
                if t.startswith('"') or not re.match(r"[A-Za-z_]", t):
                    prev = t
                    continue
                upper = t.upper()
                if prev and prev.upper() == "USING" and t.lower() in {"btree", "hash", "gin", "gist", "brin", "spgist"}:
                    if t != t.lower():
                        errors.append(f"{path}:{line}: index method '{t}' must be lowercase")
                elif upper in KEYWORDS:
                    if t != upper:
                        errors.append(f"{path}:{line}: keyword '{t}' must be UPPERCASE")
                elif t != t.lower():
                    errors.append(f"{path}:{line}: unquoted identifier '{t}' must be lowercase (or quote it)")
                prev = t

            upper_words = [w.upper() for w in words]
            # CREATE TABLE name ( col type ..., CONSTRAINT ... )
            if upper_words[:2] == ["CREATE", "TABLE"] or upper_words[:3] in (["CREATE", "TEMP", "TABLE"], ["CREATE", "TEMPORARY", "TABLE"]):
                if "TEMP" in upper_words[:3] or "TEMPORARY" in upper_words[:3]:
                    continue
                m = re.match(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"[^"]+"|\w+)\.)?("(?:[^"]|"")+"|\w+)\s*\((.*)\)\s*$',
                             stmt, re.S | re.I)
                if m:
                    table = unquote(m.group(2))
                    created_tables.append((path, line, table))
                    depth, part, parts = 0, "", []
                    for ch in m.group(3):
                        depth += ch == "("
                        depth -= ch == ")"
                        if ch == "," and depth == 0:
                            parts.append(part); part = ""
                        else:
                            part += ch
                    parts.append(part)
                    for p in parts:
                        cm = re.match(r'\s*("(?:[^"]|"")+"|\w+)', p)
                        if cm and cm.group(1).upper() not in {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "EXCLUDE", "LIKE"}:
                            created_columns.append((path, line, table, unquote(cm.group(1))))
            # ALTER TABLE name ADD [COLUMN] [IF NOT EXISTS] col type
            for am in re.finditer(r'ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?((?:"[^"]+"|\w+)\.)?("(?:[^"]|"")+"|\w+)', stmt, re.I):
                table = unquote(am.group(2))
                for add in re.finditer(r'\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?("(?:[^"]|"")+"|\w+)', stmt, re.I):
                    col = add.group(1)
                    if col.upper() not in {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK"}:
                        created_columns.append((path, line, table, unquote(col)))
            # COMMENT ON TABLE t / COMMENT ON COLUMN t.c
            if upper_words[:3] == ["COMMENT", "ON", "TABLE"]:
                cm = re.match(r'COMMENT\s+ON\s+TABLE\s+((?:"[^"]+"|\w+)\.)?("(?:[^"]|"")+"|\w+)', stmt, re.I)
                if cm:
                    table_comments.add(unquote(cm.group(2)))
            if upper_words[:3] == ["COMMENT", "ON", "COLUMN"]:
                cm = re.match(r'COMMENT\s+ON\s+COLUMN\s+(?:((?:"[^"]+"|\w+))\.)?("(?:[^"]|"")+"|\w+)\.("(?:[^"]|"")+"|\w+)', stmt, re.I)
                if cm:
                    column_comments.add((unquote(cm.group(2)), unquote(cm.group(3))))

    for path, line, table in created_tables:
        if table not in table_comments:
            errors.append(f"{path}:{line}: table {table} has no COMMENT ON TABLE")
    for path, line, table, col in created_columns:
        if (table, col) not in column_comments:
            errors.append(f"{path}:{line}: column {table}.{col} has no COMMENT ON COLUMN")
    return errors


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv] or [Path("dist/AlloyDB")]
    files = sorted({f for t in targets for f in ([t] if t.is_file() else t.rglob("*.sql"))})
    errors = check(files)
    for e in errors:
        print(e)
    print(f"{len(files)} SQL file(s) checked, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
