"""Sigma rule generation from an Argus threat profile.

Sigma spec: https://github.com/SigmaHQ/sigma-specification

What this produces for a profile:

- **One Sigma rule per `indicator` entity** - a concrete IOC detection: IP in a network
  connection, domain in a DNS query, URL in a web proxy log, file hash in a file-event log. The
  logsource mapping is picked from the IOC's apparent type (ipv4/ipv6, domain, URL, SHA256/SHA1/MD5).
  These are the detections Argus genuinely owns, because the indicators come from the investigation.

- **One SigmaHQ reference per `attack-pattern` entity (MITRE technique)** - a link to the existing,
  community-maintained SigmaHQ rules tagged with that technique. Argus does not invent a detection
  for a technique: writing one from the id alone cannot be verified (a wrong field silently never
  fires), and SigmaHQ already maintains vetted rules. Referencing them is the honest, useful move.

The IOC rules deliberately avoid any Argus-internal metadata (no quote strings, no admiralty codes,
no `x_argus_*`): the file is meant to live in SigmaHQ-shaped repositories and be consumed by sigmac
or pySigma. Argus's own trace stays on the Argus side.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from cyllex_argus.knowledge.profile import Profile

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_URL = re.compile(r"^https?://", re.I)
_SIGMA_NS = uuid.UUID("00000000-0000-0000-0000-000000000001")

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

# A GitHub code search scoped to the SigmaHQ repository for the technique's ATT&CK tag. It lands on
# the community rules tagged `attack.t<id>` (lowercase), which is how SigmaHQ labels technique rules.
_SIGMAHQ_SEARCH = "https://github.com/search?q=repo%3ASigmaHQ%2Fsigma+{tag}&type=code"


@dataclass(frozen=True)
class SigmaRule:
    """Serializes to one Sigma YAML document. `tags` is MITRE ATT&CK IDs or Sigma categories."""

    id: str
    title: str
    description: str
    author: str
    date: date
    references: tuple[str, ...]
    tags: tuple[str, ...]
    logsource: dict[str, str]
    detection: dict[str, Any]
    falsepositives: tuple[str, ...]
    level: str
    status: str = "experimental"

    def to_yaml(self) -> str:
        return _emit(_rule_to_dict(self))


@dataclass(frozen=True)
class SigmaHqRuleRef:
    """One existing SigmaHQ rule: its title and a direct, login-free link pinned to the indexed commit."""

    title: str
    url: str


@dataclass(frozen=True)
class SigmaHqReference:
    """What SigmaHQ offers for one observed MITRE technique: how many rules carry its tag, a capped
    sample of them as direct links, and a search link for the rest. `count == 0` is a coverage gap."""

    technique_id: str
    technique_name: str
    count: int
    rules: tuple[SigmaHqRuleRef, ...]
    browse_url: str


def _indicator_of(fact):
    """The indicator entity of a fact, whichever side it sits on. Data links IOCs both ways:
    `actor -uses-> indicator` (the IOC is the object) and `indicator -indicates-> actor` (the IOC
    is the subject). Return None when neither side is an indicator."""
    if fact.object.stix_type == "indicator":
        return fact.object
    if fact.subject.stix_type == "indicator":
        return fact.subject
    return None


def generate(profile: Profile, author: str = "Cyllex Argus") -> list[SigmaRule]:
    """One Sigma rule per IOC entity, whichever side of the fact it sits on. Techniques are not
    turned into rules (see `sigmahq_references`). Order is deterministic (sorted by IOC value)."""
    today = datetime.now().date()
    candidates = [(ind, fact) for fact in profile.facts if (ind := _indicator_of(fact)) is not None]
    candidates.sort(key=lambda pair: pair[0].name)

    rules: list[SigmaRule] = []
    seen_names: set[str] = set()
    for ind, fact in candidates:
        if ind.name in seen_names:
            continue
        seen_names.add(ind.name)
        rule = _ioc_rule(profile, ind, fact, today, author)
        if rule is not None:
            rules.append(rule)
    return rules


@lru_cache(maxsize=1)
def _sigmahq_index() -> dict:
    """The bundled technique -> SigmaHQ rules index (built by scripts/build_sigmahq_index.py). A
    missing or unreadable file degrades to an empty index, so references still render (count 0)."""
    try:
        return json.loads(Path(__file__).with_name("sigmahq_index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"commit": "", "techniques": {}}


def sigmahq_references(profile: Profile) -> list[SigmaHqReference]:
    """For each observed MITRE technique, what SigmaHQ already has for it (from the bundled index):
    the rule count and a capped sample of direct links. Argus references the community's vetted
    detections instead of inventing an unverifiable one. Deduped by technique id and sorted."""
    index = _sigmahq_index()
    commit = index.get("commit") or "master"
    techniques = index.get("techniques", {})
    refs: dict[str, SigmaHqReference] = {}
    for fact in profile.facts:
        obj = fact.object
        if obj.stix_type != "attack-pattern" or not obj.external_id:
            continue
        tid = obj.external_id.upper()
        if tid in refs:
            continue
        entry = techniques.get(tid, {})
        rules = tuple(
            SigmaHqRuleRef(title=r["t"], url=f"https://github.com/SigmaHQ/sigma/blob/{commit}/{r['p']}")
            for r in entry.get("r", [])
        )
        refs[tid] = SigmaHqReference(
            technique_id=tid,
            technique_name=obj.name,
            count=int(entry.get("n", 0)),
            rules=rules,
            browse_url=_SIGMAHQ_SEARCH.format(tag=f"attack.{tid.lower()}"),
        )
    return [refs[k] for k in sorted(refs)]


def references_markdown(references: list[SigmaHqReference]) -> str:
    """A Markdown page listing, per observed technique, the SigmaHQ rules that already detect it,
    written beside the IOC rules by the CLI and bundled in the download. Empty -> empty string."""
    if not references:
        return ""
    out = [
        "# SigmaHQ detection references",
        "",
        "Argus does not invent a detection for each technique. For every MITRE technique this actor",
        "is observed using, below are the existing, community-maintained SigmaHQ rules that already",
        "detect it. Deploy those vetted rules rather than a generated placeholder.",
        "",
    ]
    for r in references:
        if r.count:
            plural = "" if r.count == 1 else "s"
            out.append(f"## {r.technique_id} {r.technique_name} ({r.count} SigmaHQ rule{plural})")
            out += [f"- [{rule.title}]({rule.url})" for rule in r.rules]
            if r.count > len(r.rules):
                out.append(f"- ...and {r.count - len(r.rules)} more: {r.browse_url}")
        else:
            out.append(f"## {r.technique_id} {r.technique_name} (no SigmaHQ rule yet, a coverage gap)")
            out.append(f"- Search: {r.browse_url}")
        out.append("")
    return "\n".join(out)


def _ioc_rule(profile: Profile, ind, fact, today: date, author: str) -> SigmaRule | None:
    value = ind.name.strip()
    logsource, detection = _classify_ioc(value)
    if logsource is None:
        return None

    refs = tuple(sorted({c.location for c in fact.citations if c.location}))
    rule_id = str(uuid.uuid5(_SIGMA_NS, f"ioc:{value}"))
    return SigmaRule(
        id=rule_id,
        title=f"IOC: {value} ({logsource['category']})",
        description=_ioc_description(value, logsource["category"], profile.entity.name),
        author=author,
        date=today,
        references=refs,
        tags=_actor_tag(profile),
        logsource=logsource,
        detection=detection,
        falsepositives=("Legitimate internal reuse of the indicator (unlikely for a tracked IOC).",),
        level=_ioc_level(fact.confidence, fact.status.value),
    )


def _classify_ioc(value: str) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    """Return (logsource, detection) for a Sigma rule, or (None, None) if the IOC does not
    map to a known Sigma category. Sigma category/product pairs are the SigmaHQ conventions."""
    stripped = value.replace("[.]", ".").replace("hxxp", "http")

    try:
        ip = ip_address(stripped)
    except ValueError:
        ip = None
    if ip is not None:
        return (
            {"category": "firewall", "product": "any"},
            {"selection": {"dst_ip": str(ip)}, "condition": "selection"},
        )

    if _URL.match(stripped):
        return (
            {"category": "proxy", "product": "any"},
            {"selection": {"cs-uri": stripped}, "condition": "selection"},
        )

    if _HEX.match(stripped) and len(stripped) in _HASH_LENGTHS:
        algo = _HASH_LENGTHS[len(stripped)]
        return (
            {"category": "file_event", "product": "windows"},
            {
                "selection": {"Hashes|contains": f"{algo.upper()}={stripped.lower()}"},
                "condition": "selection",
            },
        )

    if _DOMAIN.match(stripped):
        return (
            {"category": "dns_query", "product": "windows"},
            {"selection": {"QueryName": stripped.lower()}, "condition": "selection"},
        )

    return (None, None)


_GROUP_ID = re.compile(r"^G\d+$", re.I)

_IOC_VERB = {
    "firewall": "network connections to",
    "proxy": "web requests to",
    "dns_query": "DNS lookups of",
    "file_event": "a file matching the hash",
}


def _actor_tag(profile: Profile) -> tuple[str, ...]:
    """The actor's ATT&CK group tag (e.g. `attack.g1017`), which is what an IOC is attributed to.
    An IOC rule carries this, not the actor's technique list: a single hash or domain does not
    implement every technique the group uses, and tagging it so pollutes ATT&CK coverage."""
    gid = (profile.entity.external_id or "").strip()
    return (f"attack.{gid.lower()}",) if _GROUP_ID.match(gid) else ()


def _ioc_description(value: str, category: str, actor: str) -> str:
    """A description that names the IOC for what it is: an IP/domain/URL is traffic, a hash is a file."""
    verb = _IOC_VERB.get(category, "activity involving")
    return f"Detects {verb} {value}, an indicator attributed to '{actor}' by Argus."


def _level(confidence: int, status: str) -> str:
    """Map Argus confidence + status to Sigma's `level`. Sigma recognises informational, low,
    medium, high, critical. CONTESTED never crosses `medium` - a rule that fires frequently
    off disputed evidence erodes SOC trust."""
    if status == "contested":
        return "low"
    if status == "corroborated" and confidence >= 80:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def _ioc_level(confidence: int, status: str) -> str:
    """IOC rules detect a specific tracked indicator, so a match is high-fidelity no matter how
    strong the *attribution* is. Floor at medium (never 'low', which gets a rule ignored); a
    corroborated, high-confidence indicator is 'high'."""
    if status == "corroborated" and confidence >= 80:
        return "high"
    return "medium"


def _rule_to_dict(rule: SigmaRule) -> dict:
    out = {
        "title": rule.title,
        "id": rule.id,
        "status": rule.status,
        "description": rule.description,
        "author": rule.author,
        "date": rule.date.isoformat(),
        "references": list(rule.references),
        "tags": list(rule.tags),
        "logsource": dict(rule.logsource),
        "detection": dict(rule.detection),
        "falsepositives": list(rule.falsepositives),
        "level": rule.level,
    }
    return out


# -- minimal YAML emitter -----------------------------------------------------------------
# Sigma files use plain scalars, string values, nested dicts, and lists of scalars. The
# emitter below covers exactly that shape; it does not attempt to be a general YAML writer.
# Verified against SigmaHQ examples: block style, 2-space indent, strings quoted when they
# contain special characters.

# Backslash is included even though it is legal in a plain YAML scalar: Sigma convention is
# to quote Windows paths like '\lsass.exe', and some strict parsers mis-handle plain scalars
# that start with it. Quoting is cheap and matches SigmaHQ examples.
_YAML_SPECIALS = re.compile(r"[\\:#\-{}\[\],&*!|>'\"%@`]|^\s|\s$")


def _emit(value: Any, indent: int = 0) -> str:
    if isinstance(value, dict):
        lines = []
        for key, sub in value.items():
            prefix = " " * indent + f"{key}:"
            if isinstance(sub, dict | list) and sub:
                lines.append(prefix)
                lines.append(_emit(sub, indent + 2))
            else:
                lines.append(f"{prefix} {_scalar(sub)}" if sub != [] else f"{prefix} []")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return " " * indent + "[]"
        return "\n".join(" " * indent + f"- {_scalar(item)}" for item in value)
    return " " * indent + _scalar(value)


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    if not text:
        return "''"
    if _YAML_SPECIALS.search(text):
        # YAML single-quoted scalars take backslash as a literal; only the apostrophe needs
        # to be escaped (doubled). This is the opposite of a double-quoted scalar.
        return f"'{text.replace(chr(39), chr(39) + chr(39))}'"
    return text
