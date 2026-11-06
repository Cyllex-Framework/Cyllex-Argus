import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../api/client'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'

type RetainMode = 'off' | 'errors' | 'full'

const MODES: { value: RetainMode; label: string; description: string }[] = [
  {
    value: 'off',
    label: 'Off',
    description: 'Store nothing. Smallest DB, best privacy. Debugging an unexpected rejection means re-running the pipeline.',
  },
  {
    value: 'errors',
    label: 'Errors only (recommended)',
    description: 'Keep raw prompt + response ONLY on rejections and parse failures. 90% of the debugging value at ~10% of the storage cost.',
  },
  {
    value: 'full',
    label: 'Full',
    description: 'Keep every triage + analyst exchange. Enables replay of a scoring pass without re-calling the LLM. ~370 KB per investigation on the Scattered Spider volume.',
  },
]

export function LoggingCard({ current }: { current: RetainMode }) {
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<RetainMode | null>(null)
  const [feedback, setFeedback] = useState<string | null>(null)
  const [confirmFull, setConfirmFull] = useState(false)

  const mutation = useMutation({
    mutationFn: (mode: RetainMode) =>
      apiFetch<{ retain_raw_llm: RetainMode }>('/api/settings/logging', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ retain_raw_llm: mode }),
      }),
    onSuccess: (data) => {
      setFeedback(`saved: ${data.retain_raw_llm}`)
      setPending(null)
      queryClient.invalidateQueries({ queryKey: ['settings'] })
      setTimeout(() => setFeedback(null), 3000)
    },
    onError: (error: Error) => {
      setFeedback(error.message.slice(0, 80))
      setPending(null)
      setTimeout(() => setFeedback(null), 6000)
    },
  })

  const apply = (mode: RetainMode) => {
    setPending(mode)
    mutation.mutate(mode)
  }

  const change = (mode: RetainMode) => {
    if (mode === current) return
    // Full mode captures document content, so it goes through a confirm; the rest apply directly.
    if (mode === 'full') { setConfirmFull(true); return }
    apply(mode)
  }

  return (
    <Card title="LLM trace retention">
      <p className="text-sm text-gray-400 mb-3">
        How much of each triage + analyst exchange survives in the pipeline trace. The setting takes effect for every
        event emitted from now on; existing stored rows can be reclaimed with <code className="mono">argus trace purge --raw</code>.
      </p>
      <div className="space-y-2">
        {MODES.map((mode) => (
          <label key={mode.value}
            className={`block border rounded p-3 cursor-pointer transition ${
              current === mode.value
                ? 'border-purple-500 bg-purple-900/20'
                : 'border-gray-700 hover:border-gray-600'
            }`}>
            <div className="flex items-start gap-3">
              <input
                type="radio"
                name="retain-mode"
                value={mode.value}
                checked={current === mode.value}
                disabled={mutation.isPending}
                onChange={() => change(mode.value)}
                className="mt-1"
              />
              <div className="flex-1">
                <div className="text-sm font-semibold">
                  {mode.label}
                  {pending === mode.value && mutation.isPending && (
                    <span className="text-xs text-gray-400 ml-2">saving…</span>
                  )}
                </div>
                <div className="text-xs text-gray-400 mt-1">{mode.description}</div>
              </div>
            </div>
          </label>
        ))}
      </div>
      {feedback && (
        <p className="text-xs text-gray-400 mt-3" role="status">{feedback}</p>
      )}
      <ConfirmDialog
        open={confirmFull}
        title="Enable full LLM trace retention?"
        confirmLabel="Enable full mode"
        tone="danger"
        onClose={() => setConfirmFull(false)}
        onConfirm={() => { setConfirmFull(false); apply('full') }}
      >
        <p>Full mode stores every LLM prompt and response, including document content.</p>
        <p>
          Only enable it on a store that does <strong className="text-gray-100">not</strong> handle sensitive
          or client-confidential material.
        </p>
      </ConfirmDialog>
    </Card>
  )
}
