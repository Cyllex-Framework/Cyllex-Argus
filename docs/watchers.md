# Watchers

A **watcher** turns a target into a standing monitor. It re-investigates the target on a cadence,
reusing the normal pipeline (Collector → Triage → Analyst → Validator), and after each completed
run it reports **what changed** since the last time — mostly new information, and the occasional
status change on something already known.

Watchers add no new reasoning. The scheduler fires the existing `investigate` job; a deterministic
diff compares the target entity's current assessed facts against the watcher's stored snapshot; the
resulting change events feed the Watchers page and are pushed to the configured webhooks.

Watchers is the single home for recurring monitoring: it replaces the old separate "Schedules"
page (the two were always the same `scheduled_investigations` rows underneath). The `/schedules`
URL now redirects here.

## Using it

- **Watchers** tab → **New watcher**: enter a target and a cadence (daily / weekly / monthly or a
  custom cron), and optionally the same run controls a one-off investigation has — **max docs**
  (cap the documents per run) and **concurrency** (parallel workers). Alert channels and the
  reliability floor live once in Settings, not per watcher.
- Each watcher has **Run now** (fire immediately, off-cadence), a **pause/resume** toggle, and a
  **delete** action. Running now still reconciles the feed and sends alerts exactly as a scheduled
  tick does. Pausing stops it searching and alerting but keeps everything it already found.
  Deleting removes only the watcher; the intelligence its runs produced stays in the knowledge base.
- The feed shows changes newest-first, filterable by kind:
  - **New info** — a fact, indicator or technique not seen before.
  - **New source** — a newly ingested document above the reliability floor. *(reserved; not emitted
    in Delivery 1)*
  - **Verified** — a fact moved up to corroborated.
  - **Weakened** — a fact lost corroboration.
  - **Contested** — a fact is now disputed by a credible source.

## Who can do what

- Any signed-in user sees every watcher and the full change feed (team situational awareness), and
  has their own per-user "unseen" count.
- Creating a watcher is operator+. Pausing or deleting a watcher is restricted to its owner (or an
  admin).

## Alerts

Change events are pushed to the webhooks configured under **Settings → Webhooks**. A change is sent
once (de-duplicated); a failed send is retried on the next run. Only changes backed by a source at
or above `watchers.min_reliability` (Admiralty `C` by default) produce an event. Email is not a
channel yet.

## Under the hood

A watcher is a `scheduled_investigations` row with an owner. Scheduled runs are attributed to the
watcher (`investigations.watcher_id`) and its owner, and bias collection toward recently-published
material so the watcher actually surfaces what is new. The diff runs only after the run's committed
`FINISHED` state, so it never reads mid-run assessment state.
