import { render, screen } from '@testing-library/react'
import { AdmiraltyBadge, ConfidenceBar, StatusPill } from './badges'
import { ExternalLink } from './ExternalLink'
import { ErrorCard, EmptyState } from './QueryState'
import { ApiError } from '../api/client'

test('status pills use the Cyllex tones', () => {
  render(<><StatusPill status="corroborated" /><StatusPill status="contested" /><StatusPill status="single-source" /></>)
  expect(screen.getByText('corroborated').className).toContain('text-green-400')
  expect(screen.getByText('contested').className).toContain('text-red-400')
  expect(screen.getByText('single-source').className).toContain('text-gray-300')
})

test('admiralty and confidence render their values', () => {
  render(<><AdmiraltyBadge code="B2" /><ConfidenceBar value={84} /></>)
  expect(screen.getByText('B2')).toHaveAttribute('title', expect.stringContaining('Admiralty'))
  expect(screen.getByText('84')).toBeInTheDocument()
  expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '84')
})

test('external links only for http(s), with safe rel', () => {
  render(<><ExternalLink href="https://vendor.example/r" /><ExternalLink href="javascript:alert(1)" /><ExternalLink href="memo.txt" /></>)
  const link = screen.getByRole('link')
  expect(link).toHaveAttribute('href', 'https://vendor.example/r')
  expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  expect(link).toHaveAttribute('target', '_blank')
  expect(screen.getAllByRole('link')).toHaveLength(1)
  expect(screen.getByText('javascript:alert(1)').tagName).toBe('SPAN')
})

test('error card shows the API message; empty state shows its text', () => {
  render(<><ErrorCard error={new ApiError(404, 'unknown threat')} /><EmptyState>Nothing yet</EmptyState></>)
  expect(screen.getByText('unknown threat')).toBeInTheDocument()
  expect(screen.getByText('Nothing yet')).toBeInTheDocument()
})
