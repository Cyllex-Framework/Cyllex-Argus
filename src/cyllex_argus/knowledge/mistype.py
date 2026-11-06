"""Shared heuristic for detecting LLM identity-typing mistakes.

The Analyst sometimes extracts non-organisations as `identity` SDOs — cloud providers
and SaaS platforms (because the text treats them as targets of actions: "AWS was used
for exfiltration"), sector labels (because the text names an industry rather than a
single org: "the actor targeted healthcare"), and generic job roles (because the text
names a role rather than a named entity: "IT help desks were called").

Two parts live here, and both import this module:
- the Validator (`pipeline/validator.py`) rejects a claim at ingestion time when its
  identity object matches one of the known names — a determinístic backstop for when
  the LLM ignores the prompt's negative rules.
- the Health panel (`web/api/health.py`) scans the entire store post-hoc for identity
  entities that look mistyped and offers a one-click retype.

The lists are deliberately conservative: a false positive would nag the operator to
reject or retype a legitimate organisation. When in doubt, leave a name OFF the list.
Add names here only when their appearance in the wild is almost always wrong-typed.
"""

from __future__ import annotations

from typing import Literal

MistypeSuggestion = Literal["tool", "sector-tag"]


# Technologies, cloud providers, SaaS and vendor platforms. Rename-of-type `tool`.
# When the LLM extracts these as identities it is usually because the document narrated
# an action AGAINST them (e.g. "the actor abused AWS", "targeted Cloudflare's edge"),
# and `identity` matched the "target" slot in the prompt.
_TOOL_LOOKALIKES = frozenset(name.lower() for name in (
    # Cloud providers
    "aws", "azure", "gcp", "google cloud", "digitalocean", "linode", "oracle cloud",
    # Identity/security vendors whose products are the real actor's target
    "cloudflare", "crowdstrike", "cyberark", "duo", "okta", "ping identity",
    "beyondtrust", "sentinelone", "zscaler", "microsoft defender", "defender",
    # SaaS and vendor platforms frequently named as subjects of extortion / breaches
    "klaviyo", "mailchimp", "slack", "twilio", "sendgrid", "stripe", "braintree",
    "salesforce", "signal", "zoom", "atlassian", "jira", "confluence",
    # Microsoft identity stack
    "active directory", "active directory federated services (adfs)", "adfs",
    "azure ad", "entra id", "exchange online", "sharepoint",
))

# Sector or industry labels. These should not be entities at all — they belong on
# the actor's `attributes.sectors`, not as separate SDOs.
_SECTOR_LOOKALIKES = frozenset(name.lower() for name in (
    "aerospace and defense", "aerospace", "automotive", "aviation", "logistics",
    "retail", "healthcare", "financial services", "financial-services", "insurance",
    "manufacturing", "pharmaceuticals", "energy", "telecommunications",
    "business process outsourcing (bpo)", "bpo",
    "information technology", "it service providers", "it managed service providers",
    "it help desk", "it help desks", "it help support desk", "it providers",
    "cloud identity providers",
    # Additions after the 0.15 real-DB audit — generic categories the Analyst keeps
    # extracting as identities. "SaaS applications" and "maritime" surfaced on the
    # Scattered Spider DB; "media & entertainment" came from the UNC3944 docs.
    "saas applications", "maritime", "media & entertainment", "media and entertainment",
    "government", "public sector", "education", "non-profit", "nonprofit", "ngo",
    "hospitality", "gaming", "real estate", "construction",
    # Additions after the 0.17 Carbanak resume — the Analyst extracted these financial
    # synonyms verbatim from the corpus, and without them in the vocabulary the capture
    # path never fired. "Banks" and "financial institutions" are generic categories (the
    # named organisation would be e.g. "Bank of America"); "banking" / "banking sector"
    # likewise. "Financial" alone stays OFF — too common as an adjective.
    "banks", "banking", "banking sector",
    "financial institutions", "financial sector",
))


def suggest_retype(name: str) -> MistypeSuggestion | None:
    """Return `tool` / `sector-tag` / None based on the name.

    `sector-tag` is a hint the operator should delete the entity and tag the actor
    with that sector attribute instead — the sector itself is not an SDO under STIX 2.1
    semantics, it is a property of the threat actor.
    """
    key = name.lower().strip()
    if key in _TOOL_LOOKALIKES:
        return "tool"
    if key in _SECTOR_LOOKALIKES:
        return "sector-tag"
    return None


def is_known_mistype(name: str) -> bool:
    """Shortcut for the Validator: anything the detector flags is a known mistype."""
    return suggest_retype(name) is not None
