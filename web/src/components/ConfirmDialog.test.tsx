import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'

import { ConfirmDialog } from './ConfirmDialog'

describe('ConfirmDialog', () => {
  test('type-to-confirm: button stays disabled until the exact phrase is typed, then fires', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog open title="Wipe?" confirmLabel="Wipe" confirmPhrase="DELETE" tone="danger"
        onConfirm={onConfirm} onClose={() => {}}>
        <p>Everything goes.</p>
      </ConfirmDialog>,
    )
    const confirm = screen.getByRole('button', { name: 'Wipe' })
    expect(confirm).toBeDisabled()

    const input = screen.getByLabelText('Type DELETE to confirm')
    await userEvent.type(input, 'delete') // wrong case must not pass
    expect(confirm).toBeDisabled()

    await userEvent.clear(input)
    await userEvent.type(input, 'DELETE')
    expect(confirm).toBeEnabled()

    await userEvent.click(confirm)
    expect(onConfirm).toHaveBeenCalledOnce()
  })

  test('without a phrase, the confirm button is enabled immediately', () => {
    render(
      <ConfirmDialog open title="Go?" confirmLabel="Go" onConfirm={() => {}} onClose={() => {}}>
        <p>ok</p>
      </ConfirmDialog>,
    )
    expect(screen.getByRole('button', { name: 'Go' })).toBeEnabled()
  })

  test('closed dialog renders nothing', () => {
    const { container } = render(
      <ConfirmDialog open={false} title="x" confirmLabel="x" onConfirm={() => {}} onClose={() => {}}>
        <p>hidden</p>
      </ConfirmDialog>,
    )
    expect(container).toBeEmptyDOMElement()
  })
})
