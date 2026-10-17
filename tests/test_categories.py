"""Domain categories: the offline list, the model categorizer (never the network), its cache and budget."""

import logging
import urllib.error

import pytest
from conftest import T0, dns

from tapwatch import categories, config
from tapwatch.categories import (
    AiCategorizer,
    askable,
    resolve,
    set_categories,
    set_categorizer,
    set_learned,
)
from tapwatch.detectors import NewExternalDomain, Warmup

NOW = 1_800_000_000.0  # 2027-01-15 UTC


def api(text):
    """A Messages API response as the API sends it: content blocks by type, the label in the text one."""
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 220, "output_tokens": 3}}


@pytest.fixture(autouse=True)
def clean_tables():
    set_categories({})
    set_learned({})
    set_categorizer(None)
    yield
    set_categories({})
    set_learned({})
    set_categorizer(None)


def test_labels_are_the_ut1_set_plus_the_kinds_the_list_lacks():
    from tapwatch.feeds import UT1_CATEGORIES
    assert set(UT1_CATEGORIES.values()) < categories.LABELS
    assert {"security_vendor", "conferencing", "cdn", "saas", "developer_tools", "unknown"} < categories.LABELS
    assert "unknown" in categories.SYSTEM_PROMPT and "security_vendor" in categories.SYSTEM_PROMPT


def test_categorizer_parses_one_label_strictly_and_junk_is_unknown():
    sent = []
    answers = iter([api("security_vendor"), api(" CDN.\n"), api("Sure! It is a news site."), api("advertising; unknown"),
                    {"content": []}, {"content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "saas"}]}])
    cat = AiCategorizer("k", runner=lambda body: (sent.append(body), next(answers))[1])
    assert cat.ask("vendor.example", NOW) == "security_vendor"
    assert cat.ask("cdn.example", NOW) == "cdn"           # case and punctuation stripped
    assert cat.ask("prose.example", NOW) == "unknown"     # a sentence is not a label
    assert cat.ask("two.example", NOW) == "unknown"       # two labels is not one
    assert cat.ask("empty.example", NOW) == "unknown"     # no text block
    assert cat.ask("thought.example", NOW) == "saas"      # the text block, wherever it sits
    body = sent[0]
    assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == 12 and "temperature" not in body
    assert body["messages"] == [{"role": "user", "content": "vendor.example"}]  # the registrable domain, nothing else
    assert body["system"] == categories.SYSTEM_PROMPT and body["thinking"] == {"type": "disabled"}


def test_categorizer_failures_are_empty_with_one_warning_an_hour(caplog):
    def boom(body):
        raise urllib.error.URLError("no route")
    cat = AiCategorizer("k", runner=boom)
    with caplog.at_level(logging.WARNING, logger="tapwatch"):
        assert cat.ask("a.example", NOW) == "" and cat.ask("b.example", NOW + 10) == ""
        assert cat.ask("c.example", NOW + 3600) == ""
    warnings = [r for r in caplog.records if "categorizer failed" in r.getMessage()]
    assert len(warnings) == 2 and cat.failures == 3   # once at NOW, once an hour later; every failure counted

    def http(body):
        raise urllib.error.HTTPError(categories.API_URL, 401, "unauthorized", {}, None)
    bad = AiCategorizer("k", runner=http)
    with caplog.at_level(logging.WARNING, logger="tapwatch"):
        assert bad.ask("d.example", NOW) == ""
    assert any("HTTP 401" in r.getMessage() for r in caplog.records)

    assert AiCategorizer("k", runner=lambda body: "not json").ask("e.example", NOW) == ""   # a bad shape is a failure too


def test_categorizer_budget_is_a_sliding_hour_and_failures_count():
    calls = []
    cat = AiCategorizer("k", per_hour=3, runner=lambda body: (calls.append(body["messages"][0]["content"]), api("news"))[1])
    for i in range(3):
        assert cat.ask(f"d{i}.example", NOW + i) == "news"
    assert cat.ask("d3.example", NOW + 3) == "" and cat.over_budget == 1 and len(calls) == 3
    assert cat.ask("d4.example", NOW + 3599) == "" and cat.over_budget == 2
    assert cat.ask("d5.example", NOW + 3600) == "news" and len(calls) == 4   # the first question has aged out


def test_only_public_registrable_domains_are_askable():
    assert askable("api.vendor.example") == "vendor.example" and askable("Vendor.Example.") == "vendor.example"
    assert askable("news.bbc.co.uk") == "bbc.co.uk"
    for name in ("", None, "printer", "localhost", "nas.local", "tv.lan", "hub.home", "box.internal", "pc.ts.net",
                 "5.50.168.192.in-addr.arpa", "192.168.50.7", "203.0.113.9", "2001:db8::1",
                 "host.1234"):
        assert askable(name) == "", name


def test_resolve_prefers_the_list_then_the_cache_then_the_model():
    asked = []
    set_categories({"ads.example": "advertising"})
    set_learned({"cached.example": ("saas", "2027-01-10"), "stale.example": ("cdn", "2026-11-01"),
                 "nothing.example": ("unknown", "2027-01-14")})
    cat = AiCategorizer("k", runner=lambda body: (asked.append(body["messages"][0]["content"]), api("conferencing"))[1])
    set_categorizer(cat)
    assert resolve("x.ads.example", NOW) == ("advertising", "list")      # the list, no question
    assert resolve("app.cached.example", NOW) == ("saas", "ai")           # the cache, no question
    assert resolve("cdn1.stale.example", NOW) == ("conferencing", "ai")   # 30 days old: asked again
    assert resolve("nothing.example", NOW) == ("", "")                    # cached unknown: not asked, not shown
    assert resolve("meet.fresh.example", NOW) == ("conferencing", "ai")   # the model, once
    assert resolve("call.fresh.example", NOW) == ("conferencing", "ai")   # same registrable domain: the cache
    assert resolve("nas.local", NOW) == ("", "") and resolve("192.168.50.7", NOW) == ("", "")
    assert asked == ["stale.example", "fresh.example"]


def test_without_a_categorizer_resolve_never_calls_anything():
    set_learned({"cached.example": ("saas", "2027-01-10")})
    assert resolve("a.cached.example", NOW) == ("saas", "ai")     # the cache still answers
    assert resolve("b.unseen.example", NOW) == ("", "")           # and nothing is asked


def test_unknown_answers_are_cached_but_never_shown(tmp_path):
    asked = []
    set_learned({}, tmp_path / "categories.learned.tsv")
    set_categorizer(AiCategorizer("k", runner=lambda body: (asked.append(1), api("no idea"))[1]))
    assert resolve("a.mystery.example", NOW) == ("", "") and resolve("b.mystery.example", NOW) == ("", "")
    assert len(asked) == 1 and categories.LEARNED["mystery.example"][0] == "unknown"
    assert (tmp_path / "categories.learned.tsv").read_text() == "mystery.example\tunknown\tai\t2027-01-15\n"


def test_learned_file_round_trip_and_expiry(tmp_path):
    f = tmp_path / "categories.tsv"
    f.write_text("ads.example\tadvertising\n")
    learned = tmp_path / "categories.learned.tsv"
    learned.write_text("old.example\tcdn\tai\t2026-12-01\n"      # 45 days before NOW: expired
                       "new.example\tsaas\tai\t2027-01-10\n"
                       "new.example\tnews\tai\t2027-01-12\n"     # appended later: wins
                       "bogus.example\tnot_a_label\tai\t2027-01-12\n"
                       "hand.example\tsaas\tlist\t2027-01-12\n"   # not the model's: ignored
                       "broken line\n")
    assert categories.load(str(f)) == 1   # the learned file is found beside the list
    assert categories.LEARNED == {"old.example": ("cdn", "2026-12-01"), "new.example": ("news", "2027-01-12")}
    assert resolve("a.new.example", NOW) == ("news", "ai")
    assert resolve("a.old.example", NOW) == ("", "")   # expired and no categorizer: nothing
    set_categorizer(AiCategorizer("k", runner=lambda body: api("cdn")))
    assert resolve("a.old.example", NOW) == ("cdn", "ai")
    assert learned.read_text().endswith("old.example\tcdn\tai\t2027-01-15\n")   # appended, the rest untouched
    assert categories.load(str(f)) == 1 and categories.LEARNED["old.example"] == ("cdn", "2027-01-15")
    assert categories.load(None) == 0 and categories.LEARNED == {}   # no list, no cache


def test_config_names_the_learned_file_in_feeds_dir_and_builds_the_categorizer_only_when_asked(tmp_path, monkeypatch):
    cfg = config.with_feeds({"feeds_dir": str(tmp_path)})
    assert cfg["learned_categories_file"] == str(tmp_path / "categories.learned.tsv")   # before it exists
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert categories.from_config({}) is None and categories.from_config({"categories": {"ai": True}}) is None
    monkeypatch.setenv("CAT_KEY", "sk-test")
    cat = categories.from_config({"categories": {"ai": True, "api_key_env": "CAT_KEY", "per_hour": 5}})
    assert cat.api_key == "sk-test" and cat.model == "claude-haiku-5-5" and cat.per_hour == 5
    assert categories.from_config({"categories": {"ai": False, "api_key_env": "CAT_KEY"}}) is None


def test_new_domain_carries_the_category_sources():
    from tapwatch.summarizer import Assets, summarize
    set_categories({"ads.example": "advertising"})
    set_categorizer(AiCategorizer("k", runner=lambda body: api("security_vendor")))
    nd = NewExternalDomain(Warmup(0), window=300)
    recs = [dns(T0, "a.ads.example"), dns(T0 + 1, "edr.vendor.example"), dns(T0 + 2, "nas.local")]
    cases = [c for r in recs for c in nd.feed(r)] + nd.flush()
    (c,) = cases
    assert c.facts["categories"] == ["advertising", "security_vendor"] and c.facts["category_sources"] == ["list", "ai"]
    assert "from the offline list and a model" in summarize(c, Assets())
    nd2 = NewExternalDomain(Warmup(0), window=300)
    (one,) = [x for x in nd2.feed(dns(T0, "edr.vendor.example"))] + nd2.flush()
    assert one.facts["category_sources"] == ["ai"]
    assert "A model classed it as a security vendor site (not on the offline list)" in summarize(one, Assets())


def test_new_domain_with_no_categorizer_asks_nothing():
    nd = NewExternalDomain(Warmup(0), window=300)
    (c,) = [x for x in nd.feed(dns(T0, "edr.vendor.example"))] + nd.flush()
    assert c.facts["categories"] == [] and c.facts["category_sources"] == []
