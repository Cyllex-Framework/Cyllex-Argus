"""Lazy registry of built-in enrichers.

Importing an enricher pulls its HTTP client and parser; keeping registration lazy means an
unused enricher does not pay for itself at startup.
"""

from __future__ import annotations

from cyllex_argus.enrichment.base import Enricher


def available_enrichers(virustotal_api_key: str = "", virustotal_env_api_key: str = "") -> dict[str, Enricher]:
    """Return a fresh dict of every built-in enricher instance.

    New enrichers are added here. The returned instances are independent; a caller that wants to
    stub one for a test can replace it in the dict before passing it to the runner.

    `virustotal_api_key` is the toml-stored key for the VirusTotal enricher and
    `virustotal_env_api_key` the name of the env var to read it from (empty = the default
    `VIRUSTOTAL_API_KEY`); the env var overrides the stored key at request time. The parameters
    are kept here (not globally resolved inside the enricher) so a test can instantiate the
    enricher with its own key without mutating `os.environ`.
    """
    from cyllex_argus.enrichment.crtsh import CrtShEnricher
    from cyllex_argus.enrichment.greynoise import GreyNoiseEnricher
    from cyllex_argus.enrichment.kev import CisaKevEnricher
    from cyllex_argus.enrichment.nvd import NvdEnricher
    from cyllex_argus.enrichment.urlhaus import UrlhausEnricher
    from cyllex_argus.enrichment.virustotal import VirusTotalEnricher
    return {
        CrtShEnricher.name: CrtShEnricher(),
        NvdEnricher.name: NvdEnricher(),
        UrlhausEnricher.name: UrlhausEnricher(),
        CisaKevEnricher.name: CisaKevEnricher(),
        GreyNoiseEnricher.name: GreyNoiseEnricher(),
        VirusTotalEnricher.name: VirusTotalEnricher(api_key=virustotal_api_key, env_api_key=virustotal_env_api_key),
    }
