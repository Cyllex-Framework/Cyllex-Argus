# Source Reliability

_[Back to the docs index](README.md)_

## Source reliability (Admiralty)

Every assessment carries two independent letters, and keeping them apart is the point.
**Admiralty A–F** rates the *source*: how often has this publisher turned out to be right.
**ICD 203** (next section) rates the *judgement*. Collapsing them into one number is how
intelligence products end up unfalsifiable.

Two things about this axis are easy to get wrong, and Argus used to get both wrong.

### F is the floor, not the middle

In the Admiralty system `F` means **reliability cannot be judged** — and `scoring.score`
multiplies every piece of evidence by the weight of its publisher's letter, so F suppresses the
confidence of everything that source reports. A store that has never touched this axis therefore
files CISA, NCSC-UK, ANSSI, Mandiant and Unit 42 as unjudgeable and pins their reporting to the
bottom of the scale. That is not a cautious default. It is a claim about those sources, and it
is false.

Argus ships a starting grade for publishers whose track record is well established
(`knowledge/publisher_ratings.py` — each entry carries the reason for its grade):

| Grade | Who | Why |
|---|---|---|
| **A** | National cyber agencies, law-enforcement and regulatory filings, standards bodies | Primary access to the incident, a correction record, institutional accountability for being wrong |
| **B** | Vendors and networks reporting from their own telemetry or incident response | First-hand data and a strong record, discounted one band for the commercial incentive in attribution |
| **C** | Curated catalogs and reporting with a good record but no primary access | Fairly reliable, and dependent on whoever they are citing |

The table lists **only** established track records. A publisher it cannot speak to stays at F,
which is then accurate rather than merely cautious — so expect it to leave plenty of sources
ungraded, and rate those yourself.

**In the interface:** the Sources page offers the grades with the reason for each one, behind a
disclosure so the table is reviewable before anything is applied, and one button applies them.
The dashboard's Data health counts them (“N publishers Argus can grade”) and links here, because
that is the screen an operator lands on.

**From the CLI:**

```bash
argus sources rate-known --dry-run   # the proposal, with the reason for every grade
argus sources rate-known --yes       # apply, then rescore every fact those sources support
```

Precedence, weakest to strongest: this table → `[publishers]` in `argus.toml` → whatever
`argus sources set-reliability` put on the row. **Your judgement always wins**, and a grade a
human set is never overwritten unless you ask with `--include-rated`.

### One publisher row per organisation, not per byline

`scoring.score` keeps one piece of evidence per `publisher_id` and derives corroboration from
how many of those there are — **the publisher row is the unit of independence**. So when the
same organisation publishes under several bylines, it corroborates itself. This is not
hypothetical: a real 46-document store held CISA under seven bylines, Microsoft under five and
NCSC-UK under four, and facts came out "corroborated" on the strength of one agency agreeing
with itself.

Publisher identity is therefore the **registrable domain**, whenever that domain belongs to a
single organisation (`knowledge/publisher_identity.py`):

- It reduces to the registrable domain, not the hostname, so `www.cisa.gov` and
  `us-cert.cisa.gov` are one source — while keeping the public-suffix distinction, so
  `ncsc.gov.uk` does not collapse into `gov.uk`, the entire British government.
- It **refuses** domains that host unrelated authors — medium.com, substack.com, github.com,
  the web archives. There the domain says nothing about who wrote the piece, and folding them
  together would fuse independent researchers into one voice. A missed merge overstates
  independence for one organisation; a wrong merge understates it for two and hides real
  disagreement. The second is worse, so identity falls back to the byline and the duplicate rows
  stay.
- A publisher's domain is Analyst output — model-written text from an untrusted document — so
  nothing here raises. A string that is not a hostname simply does not identify an organisation.

Every byline is remembered in `publisher_names`, so merging destroys no evidence:
`argus sources set-reliability "<old byline>"` keeps working, and `argus sources list` shows
which names each row speaks for.

**In the interface:** the Sources page lists each organisation with the rows it would absorb and
how many documents each holds, and merges them one organisation at a time or all at once. Data
health counts the rows and links here.

**From the CLI:**

```bash
argus sources merge-duplicates --dry-run   # the plan: which rows are one organisation
argus sources merge-duplicates --yes       # fold them, then rescore the affected facts
argus sources merge "<keep>" "<drop>"...   # by hand, for cases the rules deliberately refuse
```

**Expect confidence to go down** when you merge. A merge can only remove supporters, and the
scores it lowers were overstated before. Run the merge *before* grading: it means rating ~20
organisations instead of 38 rows.

`argus sources list` points at both commands whenever either has something to fix — a screen
that shows a problem should name its solution.


## ICD 203 analytic confidence

Alongside Admiralty (source reliability, A — F), every assessment carries an **ICD 203 level** —
HIGH / MODERATE / LOW. Admiralty answers "how reliable is the publisher?"; ICD 203 answers "how
confident is the analyst in the judgement?". Derived conservatively by default; the analyst can
override from the Threat profile with a required rationale. See `knowledge.models.confidence_level`
for the derivation table.


---
_[Back to the docs index](README.md)_
