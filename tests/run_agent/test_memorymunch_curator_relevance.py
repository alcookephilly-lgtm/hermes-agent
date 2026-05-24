import importlib.util
from pathlib import Path


PLUGIN_PATH = Path.home() / ".hermes" / "plugins" / "memorymunch" / "__init__.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("memorymunch_plugin_under_test", PLUGIN_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_curator_drops_activation_only_personal_noise_for_plugin_audit_query():
    mm = load_plugin()
    provider = mm.MemoryMunchProvider()
    rows = [
        {
            "id": "active::current::1",
            "provenance_class": "ACTIVE_SESSION_LEDGER_CURRENT",
            "source": "ACTIVE_SESSION_LEDGER",
            "activation_weight": 1.0,
            "content_preview": "User asked to audit Hermes MemoryMunch plugin parity against OpenClaw.",
        },
        {
            "atom_id": "tg-7475127948::al-cooke-closed-on-a-property-at-245-lak#semantic",
            "provenance_class": "OWN_SCOPE",
            "source": "vault,activation",
            "activation_weight": 0.95,
            "content_preview": "Al Cooke closed on 245 Lake View Drive, Sebring FL.",
        },
        {
            "atom_id": "tg-7475127948::al-cooke-s-three-confirmed-email-address#semantic",
            "provenance_class": "OWN_SCOPE",
            "source": "vault,activation",
            "activation_weight": 0.94,
            "content_preview": "Al Cooke's three confirmed email addresses were used when an agent sent an audit document.",
        },
        {
            "atom_id": "tg-7475127948::income-streams#semantic",
            "provenance_class": "OWN_SCOPE",
            "source": "vault,activation",
            "activation_weight": 0.94,
            "content_preview": "Al Cooke has three income streams: real estate, mortgage, and trading.",
        },
    ]

    curated = provider._curate_rows_for_query(
        rows,
        "Hermes MemoryMunch OpenClaw curator capture janitor parity audit plugin missed issues",
        keep_if_no_match=0,
        max_rows=6,
    )

    text = "\n".join(str(r.get("content_preview") or "") for r in curated)
    assert "Hermes MemoryMunch plugin parity" in text
    assert "Lake View Drive" not in text
    assert "email addresses" not in text
    assert "income streams" not in text


def test_curator_keeps_absolute_rule_atoms_even_when_query_terms_do_not_match():
    mm = load_plugin()
    provider = mm.MemoryMunchProvider()
    rows = [
        {
            "atom_id": "tg-7475127948::absolute-rule-never-ignore-a-rule-atom-i#semantic",
            "memory_type": "semantic",
            "provenance_class": "OWN_SCOPE",
            "source": "vault,activation",
            "activation_weight": 0.94,
            "content_preview": "rule::never-ignore-rule-atoms — RULE atoms are ABSOLUTE and must be obeyed.",
        }
    ]

    curated = provider._curate_rows_for_query(
        rows,
        "write a file path and prompt for another agent",
        keep_if_no_match=0,
        max_rows=6,
    )

    assert curated
    assert "ABSOLUTE" in curated[0]["content_preview"]


def test_query_terms_ignore_generic_memorymunch_audit_words():
    mm = load_plugin()
    provider = mm.MemoryMunchProvider()

    terms = provider._query_terms(
        "Hermes MemoryMunch OpenClaw plugin audit parity fix prompt document issue Lake View"
    )

    assert "memorymunch" not in terms
    assert "hermes" not in terms
    assert "openclaw" not in terms
    assert "plugin" not in terms
    assert "audit" not in terms
    assert "lake" in terms
    assert "view" in terms
