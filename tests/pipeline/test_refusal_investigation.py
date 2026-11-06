"""A safety refusal during analysis is recorded as a distinct `refused` event (not a generic
`failed`), the run still finishes, and the reason names the policy + the fix (another model)."""

from __future__ import annotations

from cyllex_argus.knowledge.models import InvestigationState
from cyllex_argus.llm.base import LLMRefused
from tests.pipeline.test_investigation import World
from tests.support import ScriptedLLM


class _AnalystRefuses(ScriptedLLM):
    """Refuses every analyst call on safety grounds; triage/search/summary behave normally."""

    def _handle(self, request):
        if request.prompt_version.startswith("analyst"):
            raise LLMRefused(category="cyber", explanation="blocked under policy")
        return super()._handle(request)


def test_refused_analysis_is_recorded_as_refused_and_run_finishes(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path, llm=_AnalystRefuses())
    report = world.pipeline.investigate("Scattered Spider")

    # One refused document must not abort the whole run (same resilience as a failed document).
    assert report.state is InvestigationState.FINISHED

    events = world.recorder.list_events(report.investigation_id)
    refused = [e for e in events if e.decision == "refused"]
    assert refused, "a safety refusal must be recorded with decision 'refused', not 'failed'"
    assert all(e.stage == "analyst" for e in refused)
    reason = refused[0].reason or ""
    assert "safety policy" in reason.lower()
    assert "cyber" in reason.lower()
    # And no analyst event for the refused doc was mislabelled as a generic failure.
    assert not [e for e in events if e.stage == "analyst" and e.decision == "failed"]
