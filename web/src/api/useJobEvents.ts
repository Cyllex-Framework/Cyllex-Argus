import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, apiRequest } from './client'
import { readEventStream, type SseMessage } from './sse'
import type { Job, JobEvent } from './types'

/**
 * How hard to try when the stream drops: up to `attempts` reconnects in a row that bring no new event, `delayMs`
 * apart. Mutable so tests can drop the delay.
 */
export const STREAM_RETRY = { attempts: 3, delayMs: 1000 }

function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms)
    signal.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
  })
}

/**
 * Follow a job's progress over SSE, read with `fetch` so the request can carry the token header (`EventSource`
 * cannot send headers, and the token never goes in a URL). Events are de-duplicated by `seq`, so a reconnect cannot
 * repeat lines. `ended` turns true once the stream's `end` event arrives; `job` is then the final job, or null when
 * the server no longer knows it. A dropped connection (a network error, or the body ending without `end`) reconnects
 * with `?after=<last seq>`; `lost` (with `ended`, and no job) means the stream was given up: the server refused it,
 * as a restarted one does with a 404, or it kept dropping. The job's outcome is then unknown, so it must not look
 * "running" forever.
 */
export function useJobEvents(jobId: string | null): { events: JobEvent[]; job: Job | null; ended: boolean; lost: boolean } {
  const [events, setEvents] = useState<JobEvent[]>([])
  const [job, setJob] = useState<Job | null>(null)
  const [ended, setEnded] = useState(false)
  const [lost, setLost] = useState(false)
  const client = useQueryClient()

  useEffect(() => {
    setEvents([])
    setJob(null)
    setEnded(false)
    setLost(false)
    if (!jobId) return
    const controller = new AbortController()
    const { signal } = controller
    const path = `/api/jobs/${encodeURIComponent(jobId)}/events`
    let lastSeq = 0

    // Returns true at the end event, which stops the reading.
    const onMessage = (message: SseMessage): boolean => {
      if (message.event === 'end') {
        let final: unknown = null
        try {
          final = JSON.parse(message.data)
        } catch {
          // an unreadable final state reads as a job the server no longer knows
        }
        setJob(typeof final === 'object' && final !== null ? (final as Job) : null)
        setEnded(true)
        void client.invalidateQueries()
        return true
      }
      if (message.event !== 'message') return false
      let event: JobEvent
      try {
        event = JSON.parse(message.data) as JobEvent
      } catch {
        return false
      }
      if (typeof event?.seq !== 'number') return false
      lastSeq = Math.max(lastSeq, event.seq)
      setEvents((previous) =>
        previous.length && previous[previous.length - 1].seq >= event.seq ? previous : [...previous, event],
      )
      return false
    }

    async function follow(): Promise<void> {
      let drops = 0
      for (;;) {
        const seqBefore = lastSeq
        try {
          const response = await apiRequest(lastSeq ? `${path}?after=${lastSeq}` : path, {
            headers: { Accept: 'text/event-stream' },
            signal,
          })
          if (!response.body) break
          if (await readEventStream(response.body, onMessage)) return
          // The body ended without the end event: the connection dropped (e.g. the server stopped).
        } catch (error) {
          if (signal.aborted) return
          if (error instanceof ApiError) break // refused (404 after a restart, 401): retrying cannot help
          // a network error: reconnect below
        }
        if (signal.aborted) return
        drops = lastSeq > seqBefore ? 1 : drops + 1
        if (drops > STREAM_RETRY.attempts) break
        await pause(STREAM_RETRY.delayMs, signal)
        if (signal.aborted) return
      }
      setLost(true)
      setEnded(true)
      void client.invalidateQueries()
    }

    void follow()
    return () => controller.abort()
  }, [jobId, client])

  return { events, job, ended, lost }
}
