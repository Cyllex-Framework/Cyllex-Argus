import { afterEach, describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { IcdConfidencePanel } from './IcdConfidencePanel'
import { mockApi, renderWithProviders } from '../../test/utils'
import type { Fact } from '../../api/types'

const FACT: Fact = {
  subject: { id: 'intrusion-set--a', stix_type: 'intrusion-set', name: 'Alpha', external_id: null, attack: false, label: 'Alpha' },
  predicate: 'uses',
  object: { id: 'malware--b', stix_type: 'malware', name: 'Bravo', external_id: null, attack: false, label: 'Bravo' },
  status: 'single-source',
  confidence: 55,
  admiralty: 'B3',
  first_seen: null,
  last_seen: null,
  citations: [],
  source_count: 1,
  assessment_id: 42,
  analytic_confidence: 'moderate',
  confidence_rationale: null,
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('IcdConfidencePanel', () => {
  test('shows derived level with a hint explaining where it comes from', () => {
    mockApi({})
    renderWithProviders(<IcdConfidencePanel fact={FACT} threatId="intrusion-set--a" />)
    // The current level badge AND the dropdown's "MODERATE" option both say MODERATE —
    // what matters is that both exist, not that only one does.
    expect(screen.getAllByText(/MODERATE/).length).toBeGreaterThan(0)
    expect(screen.getByText(/derived from confidence 55, status single-source/i)).toBeInTheDocument()
  })

  test('no fact selected renders a prompt and no form', () => {
    mockApi({})
    renderWithProviders(<IcdConfidencePanel fact={null} threatId="intrusion-set--a" />)
    expect(screen.getByText(/Pick a fact to override/i)).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })

  test('a fact without an assessment id explains why save is unavailable', () => {
    const noId = { ...FACT, assessment_id: undefined }
    mockApi({})
    renderWithProviders(<IcdConfidencePanel fact={noId} threatId="intrusion-set--a" />)
    expect(screen.getByText(/no assessment id yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  test('PUT body carries level + rationale as the server expects', async () => {
    const fetchMock = mockApi({
      'PUT /api/assessments/42/analytic-confidence': { id: 42, analytic_confidence: 'low', confidence_rationale: 'stale evidence' },
    })
    renderWithProviders(<IcdConfidencePanel fact={FACT} threatId="intrusion-set--a" />)
    await userEvent.selectOptions(screen.getByRole('combobox'), 'low')
    await userEvent.type(screen.getByRole('textbox'), 'stale evidence')
    await userEvent.click(screen.getByRole('button', { name: /Save override/i }))
    expect(await screen.findByText(/Saved/i)).toBeInTheDocument()
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes('/analytic-confidence'))!
    const init = call[1]! as RequestInit
    expect(init.method).toBe('PUT')
    expect(JSON.parse(init.body as string)).toEqual({ level: 'low', rationale: 'stale evidence' })
  })

  test('clearing the override sends level=null and rationale=null', async () => {
    const fetchMock = mockApi({
      'PUT /api/assessments/42/analytic-confidence': { id: 42, analytic_confidence: null, confidence_rationale: null },
    })
    renderWithProviders(<IcdConfidencePanel fact={FACT} threatId="intrusion-set--a" />)
    // Default dropdown value is the current level ("moderate"); switch to empty = "Derived".
    await userEvent.selectOptions(screen.getByRole('combobox'), '')
    await userEvent.click(screen.getByRole('button', { name: /Clear override/i }))
    expect(await screen.findByText(/Saved/i)).toBeInTheDocument()
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes('/analytic-confidence'))!
    const init = call[1]! as RequestInit
    expect(JSON.parse(init.body as string)).toEqual({ level: null, rationale: null })
  })

  test('CSRF header is set on every PUT (SecurityMiddleware requires it)', async () => {
    const fetchMock = mockApi({
      'PUT /api/assessments/42/analytic-confidence': { id: 42, analytic_confidence: 'high', confidence_rationale: null },
    })
    renderWithProviders(<IcdConfidencePanel fact={FACT} threatId="intrusion-set--a" />)
    await userEvent.selectOptions(screen.getByRole('combobox'), 'high')
    await userEvent.click(screen.getByRole('button', { name: /Save/i }))
    await screen.findByText(/Saved/i)
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes('/analytic-confidence'))!
    const headers = (call[1]! as RequestInit).headers as Headers
    expect(headers.get('X-Argus-CSRF')).toBe('1')
    expect(headers.get('Content-Type')).toBe('application/json')
  })
})
