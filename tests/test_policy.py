from pathlib import Path

from cleanroom.policy import (Policy, extract_policy, host_matches, merge_llm_rules, path_matches,
                              split_clauses)

DEMO_RULES = (Path(__file__).resolve().parents[1] / "demo" / "rules.txt").read_text()


def kinds(pol):
    return {(r.kind, r.target) for r in pol.rules}


def test_demo_rules_extract_expected_policy():
    pol = extract_policy(DEMO_RULES)
    k = kinds(pol)
    assert ("forbid_file", "test_labels.csv") in k
    assert ("allow_file", "train.csv") in k and ("allow_file", "test.csv") in k
    assert ("deny_network", "") in k
    assert ("forbid_external_data", "") in k
    assert ("require_reproducible", "") in k


def test_every_rule_quotes_text_verbatim_with_clause_id():
    pol = extract_policy(DEMO_RULES)
    for r in pol.rules:
        assert r.quote in DEMO_RULES
        assert r.clause_id
    forb = pol.of("forbid_file")[0]
    assert forb.clause_id == "1.2"
    assert "must not be read" in forb.quote


def test_mixed_sentence_splits_polarity():
    pol = extract_policy("You may use train.csv, but you must not open private_test.parquet.")
    k = kinds(pol)
    assert ("allow_file", "train.csv") in k
    assert ("forbid_file", "private_test.parquet") in k
    assert ("allow_file", "private_test.parquet") not in k


def test_hosts_allowed_and_forbidden():
    text = ("5.1 You may download pretrained weights from huggingface.co.\n"
            "5.2 Scraping data from kaggle.com is prohibited.\n")
    pol = extract_policy(text)
    assert ("allow_host", "huggingface.co") in kinds(pol)
    assert ("forbid_host", "kaggle.com") in kinds(pol)
    assert pol.host_rule("cdn.huggingface.co")[0] == "allowed"
    assert pol.host_rule("www.kaggle.com")[0] == "forbidden"
    np = pol.sprite_network_policy()
    assert np["rules"][0] == {"domain": "huggingface.co", "action": "allow"}
    assert np["rules"][-1] == {"domain": "*", "action": "deny"}


def test_offline_rule_denies_unlisted_hosts():
    pol = extract_policy("Internet access is disabled during evaluation.")
    status, rule = pol.host_rule("example.org")
    assert status == "denied_by_default" and rule.kind == "deny_network"


def test_silent_rules_mark_hosts_unlisted_and_note_it():
    pol = extract_policy("Submit a CSV with columns id and pred.")
    assert pol.host_rule("example.org")[0] == "unlisted"
    assert any("internet" in n for n in pol.notes)


def test_conflict_forbidden_wins():
    pol = extract_policy("1. You may use extra.csv.\n2. Do not use extra.csv.")
    assert ("forbid_file", "extra.csv") in kinds(pol)
    assert ("allow_file", "extra.csv") not in kinds(pol)


def test_llm_rules_need_verbatim_quote():
    text = "3. Pseudo-labelling on the test set is allowed."
    pol = merge_llm_rules(extract_policy(text), text, [
        {"kind": "forbid_file", "target": "secret.csv", "quote": "Never touch secret.csv"},   # invented
        {"kind": "allow_external_data", "target": "", "quote": "Pseudo-labelling on the test set is allowed."},
    ])
    assert ("forbid_file", "secret.csv") not in kinds(pol)
    assert ("allow_external_data", "") in kinds(pol)
    assert any("Dropped LLM rule" in n for n in pol.notes)


def test_split_clauses_numbering_and_headings():
    cl = split_clauses("1. Data\n1.1 Use train.csv. Keep it local.\n- bullet test_labels.csv is forbidden")
    ids = [c.clause_id for c in cl]
    assert "1.1 (sentence 1)" in ids and "1.1 (sentence 2)" in ids
    assert not any(c.text == "Data" for c in cl)


def test_matchers_and_roundtrip(tmp_path):
    assert path_matches("data/test_labels.csv", "test_labels.csv")
    assert path_matches("/abs/x/data/test_labels.csv", "data/test_labels.csv")
    assert not path_matches("data/test.csv", "test_labels.csv")
    assert path_matches("data/private_1.csv", "private_*.csv")
    assert host_matches("a.b.example.com", "example.com")
    assert not host_matches("badexample.com", "example.com")
    pol = extract_policy(DEMO_RULES)
    pol.save(tmp_path / "p.json")
    assert Policy.load(tmp_path / "p.json").to_dict() == pol.to_dict()
