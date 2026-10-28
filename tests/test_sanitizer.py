import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sanitizer as core  # noqa: E402


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def test_deterministic_same_salt():
    a, b = core.Anonymizer("s1"), core.Anonymizer("s1")
    for strat in ("email", "name", "phone", "credit_card", "hash", "address"):
        assert a.anonymize(strat, "jane@acme.com") == b.anonymize(strat, "jane@acme.com")


def test_different_salt_changes_output():
    assert core.Anonymizer("s1").anonymize("email", "x@y.com") != core.Anonymizer("s2").anonymize("email", "x@y.com")


def test_different_inputs_differ():
    a = core.Anonymizer("s1")
    emails = {a.anonymize("email", f"user{i}@corp.com") for i in range(2000)}
    assert len(emails) == 2000  # unique-constraint safe


def test_never_leaks_input():
    a = core.Anonymizer("s1")
    out = a.anonymize("email", "jane.doe@acme.com")
    assert "jane" not in out and "acme" not in out and out.endswith("@example.com")


def test_credit_card_is_luhn_valid():
    a = core.Anonymizer("s1")
    for i in range(50):
        assert luhn_ok(a.anonymize("credit_card", f"41111111111111{i:02d}"))


def test_special_strategies():
    a = core.Anonymizer("s1")
    assert a.anonymize("email", None) is None
    assert a.anonymize("null", "x") is None
    assert a.anonymize("keep", "x") == "x"
    assert a.anonymize("redact", "secret") == "[REDACTED]"
    assert len(a.anonymize("hash", "secret")) == 32


def test_load_rules_ok(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"tables": {"users": {"columns": {"email": "email"}}}}))
    r = core.load_rules(p)
    assert r.schema == "public"
    assert r.tables["users"].columns == {"email": "email"}


def test_load_rules_bad_strategy(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"tables": {"users": {"columns": {"email": "emial"}}}}))
    with pytest.raises(core.RulesError):
        core.load_rules(p)


def test_shipped_rules_file_valid():
    core.load_rules(Path(__file__).resolve().parents[1] / "rules.json")


def test_redact_url():
    assert core.redact_url("postgresql://bob:s3cr3t@db:5432/app") == "postgresql://bob:****@db:5432/app"
