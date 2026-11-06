"""A defensible starting Admiralty rating for publishers whose track record is established.

Why this exists. A store rates every new publisher `F`, and in the Admiralty system F does not
mean "average" — it means *reliability cannot be judged*, and it is the floor of the scale that
`scoring.score` multiplies evidence by. On a real store that produced 85% of all assessments
sitting at the confidence floor, not because the reporting was weak but because the source axis
was never used: CISA, NCSC-UK, Mandiant, Microsoft, Unit 42, CrowdStrike and ANSSI were all
filed as "unjudgeable". Leaving that default in place is not neutrality. It is an active claim
about every source in the store, and it is false.

So Argus ships a starting grade for the publishers it can recognise by domain. Three rules keep
it honest:

1. **Only well-established track records are listed.** A publisher this table cannot speak to
   stays at F, which is then accurate: nobody has judged it yet. The table is deliberately short
   for that reason — it is not a directory of the industry.
2. **The grade is reliability, not access or prestige.** Admiralty A–F asks how often this source
   has turned out to be right, which is why primary-data networks sit alongside national
   agencies, and why a vendor with excellent telemetry and a commercial interest in naming an
   adversary sits one band below a CERT that answers to a legislature.
3. **The operator always wins.** `config.publishers` overrides this table, and
   `argus sources set-reliability` overrides both. These are a starting point for an analyst's
   judgement, never a substitute for it — which is the whole point of keeping source reliability
   on its own axis, separate from the ICD 203 analytic confidence.

Grades as used here:

* **A** — national cyber agencies, law-enforcement and regulatory filings, and standards bodies.
  Primary access to the incident, a correction record, and institutional accountability for
  being wrong.
* **B** — vendors and networks reporting from their own telemetry or incident response. First-hand
  data and a strong record, discounted one band for the commercial incentive in attribution.
* **C** — curated catalogs and reporting with a good record but no primary access. Fairly
  reliable, and dependent on whoever they are citing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnownPublisher:
    """One entry: the organisation's registrable domain, a label, the grade and why."""
    domain: str
    name: str
    reliability: str
    rationale: str


_AGENCIES = (
    ("cisa.gov", "CISA", "US cyber defence agency; joint advisories with primary incident access"),
    ("ncsc.gov.uk", "NCSC UK", "UK national cyber security centre; primary incident access"),
    ("cyber.gc.ca", "Canadian Centre for Cyber Security", "Canadian national cyber agency"),
    ("cyber.gov.au", "ACSC / ASD", "Australian Signals Directorate's cyber security centre"),
    ("ssi.gouv.fr", "ANSSI / CERT-FR", "French national cyber security agency"),
    ("bsi.bund.de", "BSI", "German federal information security office"),
    ("ncsc.govt.nz", "NCSC New Zealand", "New Zealand national cyber security centre"),
    ("nsa.gov", "NSA", "US signals intelligence agency; co-signs joint advisories"),
    ("defense.gov", "US Department of Defense", "Hosts the NSA and DoD joint advisories"),
    ("fbi.gov", "FBI", "US federal law enforcement; primary investigative access"),
    ("ic3.gov", "FBI IC3", "FBI's internet crime complaint centre; primary reporting"),
    ("justice.gov", "US Department of Justice", "Indictments are sworn primary legal documents"),
    ("treasury.gov", "US Treasury / OFAC", "Sanctions designations are primary legal records"),
    ("europol.europa.eu", "Europol", "EU law enforcement agency; primary operational access"),
    ("enisa.europa.eu", "ENISA", "EU agency for cybersecurity"),
    ("jpcert.or.jp", "JPCERT/CC", "Japanese national CERT"),
    ("krcert.or.kr", "KrCERT/CC", "South Korean national CERT"),
    ("cert.br", "CERT.br", "Brazilian national CERT"),
    ("cert.pl", "CERT Polska", "Polish national CERT; primary incident access"),
    ("sec.gov", "SEC EDGAR", "8-K and 10-K filings are the victim's own accountable disclosure"),
    ("nist.gov", "NIST / NVD", "US standards body; the vulnerability catalogue of record"),
    ("mitre.org", "MITRE", "Custodian of ATT&CK, CVE and CWE"),
    ("cisecurity.org", "CIS / MS-ISAC", "US state and local government ISAC"),
    ("first.org", "FIRST", "The CERT community's own coordinating body; CVSS custodian"),
)

_PRIMARY_TELEMETRY = (
    ("mandiant.com", "Mandiant", "Incident response from first-hand engagements"),
    ("google.com", "Google Threat Intelligence", "Mandiant plus Google's own telemetry"),
    ("microsoft.com", "Microsoft Threat Intelligence", "Telemetry across Windows, Azure and M365"),
    ("crowdstrike.com", "CrowdStrike", "Endpoint telemetry and incident response"),
    ("paloaltonetworks.com", "Unit 42", "Palo Alto Networks telemetry and incident response"),
    ("talosintelligence.com", "Cisco Talos", "Cisco network and email telemetry"),
    ("sentinelone.com", "SentinelOne", "Endpoint telemetry and research"),
    ("trendmicro.com", "Trend Micro", "Endpoint and network telemetry"),
    ("eset.com", "ESET", "Endpoint telemetry; long APT research record"),
    ("welivesecurity.com", "ESET WeLiveSecurity", "ESET's research publication"),
    ("kaspersky.com", "Kaspersky", "Endpoint telemetry; long APT research record"),
    ("securelist.com", "Kaspersky Securelist", "Kaspersky's research publication"),
    ("bitdefender.com", "Bitdefender", "Endpoint telemetry and research"),
    ("checkpoint.com", "Check Point Research", "Network telemetry and research"),
    ("group-ib.com", "Group-IB", "Incident response and underground monitoring"),
    ("trellix.com", "Trellix", "Endpoint and network telemetry"),
    ("proofpoint.com", "Proofpoint", "Email telemetry at scale"),
    ("secureworks.com", "Secureworks CTU", "Incident response and managed detection telemetry"),
    ("sophos.com", "Sophos", "Endpoint telemetry and incident response"),
    ("fortinet.com", "Fortinet FortiGuard", "Network and firewall telemetry at scale"),
    ("broadcom.com", "Symantec Threat Hunter Team", "Endpoint telemetry; long research record"),
    ("rapid7.com", "Rapid7", "Incident response and vulnerability research"),
    ("splunk.com", "Splunk Threat Research", "Detection engineering from customer telemetry"),
    ("elastic.co", "Elastic Security Labs", "Endpoint telemetry and detection research"),
    ("dragos.com", "Dragos", "OT and ICS incident response; the primary source in that domain"),
    ("redcanary.com", "Red Canary", "Managed detection telemetry"),
    ("huntress.com", "Huntress", "Managed detection telemetry, SMB estate"),
    ("volexity.com", "Volexity", "Incident response; repeated first discovery of 0-days"),
    ("nccgroup.com", "NCC Group", "Incident response and offensive research"),
    ("withsecure.com", "WithSecure", "Incident response and research"),
    ("cybereason.com", "Cybereason", "Endpoint telemetry and incident response"),
    ("zscaler.com", "Zscaler ThreatLabz", "Proxy telemetry at scale"),
    ("cloudflare.com", "Cloudflare", "Network telemetry at scale; primary DDoS data"),
    ("akamai.com", "Akamai", "Network and CDN telemetry"),
    ("recordedfuture.com", "Recorded Future / Insikt", "Collection infrastructure and research"),
    ("intel471.com", "Intel 471", "Underground collection with a strong record"),
    ("flashpoint.io", "Flashpoint", "Underground collection"),
    ("shadowserver.org", "Shadowserver Foundation", "Primary internet-wide scanning and sinkhole data"),
    ("spamhaus.org", "Spamhaus", "Primary abuse and reputation data"),
    ("team-cymru.com", "Team Cymru", "Primary netflow and BGP data"),
    ("greynoise.io", "GreyNoise", "Primary internet-scan telemetry"),
    ("censys.io", "Censys", "Primary internet-wide scanning"),
    ("shodan.io", "Shodan", "Primary internet-wide scanning"),
    ("silentpush.com", "Silent Push", "Primary DNS and infrastructure collection"),
    ("domaintools.com", "DomainTools", "Primary DNS and registration history"),
)

_CURATED = (
    ("fraunhofer.de", "Malpedia / Fraunhofer FKIE",
     "Curated malware and actor catalogue with an active correction record"),
    ("abuse.ch", "abuse.ch", "Community-fed abuse feeds with active curation"),
    ("virustotal.com", "VirusTotal", "Aggregates third-party verdicts; no verdict of its own"),
    ("alienvault.com", "AlienVault OTX", "Community-contributed indicators, lightly curated"),
    ("krebsonsecurity.com", "KrebsOnSecurity", "Investigative reporting with a long accuracy record"),
    ("therecord.media", "The Record", "Security reporting with a good accuracy record"),
    ("bleepingcomputer.com", "BleepingComputer", "Security reporting, often first; cites its sources"),
    ("reuters.com", "Reuters", "Wire service with a strong corrections policy"),
    ("apnews.com", "Associated Press", "Wire service with a strong corrections policy"),
    ("cyberscoop.com", "CyberScoop", "Security and policy reporting"),
    ("securityweek.com", "SecurityWeek", "Security trade reporting; cites its sources"),
    ("wired.com", "WIRED", "Long-form investigative technology reporting"),
)

KNOWN_PUBLISHERS: tuple[KnownPublisher, ...] = tuple(
    KnownPublisher(domain=domain, name=name, reliability=grade, rationale=rationale)
    for grade, group in (("A", _AGENCIES), ("B", _PRIMARY_TELEMETRY), ("C", _CURATED))
    for domain, name, rationale in group
)

_BY_DOMAIN: dict[str, KnownPublisher] = {entry.domain: entry for entry in KNOWN_PUBLISHERS}


def known_rating(org_key: str | None) -> KnownPublisher | None:
    """The starting grade for this organisation, or None when Argus cannot speak to it.

    None is the honest answer for most of the internet, and it leaves the publisher at F —
    "reliability cannot be judged" — which is exactly what is true until an analyst judges it.
    """
    if not org_key:
        return None
    return _BY_DOMAIN.get(org_key.strip().lower())
