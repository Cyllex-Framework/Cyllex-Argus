import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ScopeSwitch } from './ScopeSwitch'

test('marks the current scope pressed and reports a change', async () => {
  const onChange = vi.fn()
  render(<ScopeSwitch value="everything" onChange={onChange} />)
  expect(screen.getByRole('button', { name: 'Everything known' })).toHaveAttribute('aria-pressed', 'true')
  expect(screen.getByRole('button', { name: 'This investigation' })).toHaveAttribute('aria-pressed', 'false')
  await userEvent.click(screen.getByRole('button', { name: 'This investigation' }))
  expect(onChange).toHaveBeenCalledWith('investigation')
})

test('an empty contribution disables "This investigation" and explains why', async () => {
  const onChange = vi.fn()
  render(<ScopeSwitch value="everything" onChange={onChange} investigationEmpty />)
  const button = screen.getByRole('button', { name: 'This investigation' })
  expect(button).toBeDisabled()
  expect(screen.getByText('This investigation contributed no facts about this entity yet.')).toHaveClass('text-xs', 'text-gray-400', 'mt-1')
  await userEvent.click(button)
  expect(onChange).not.toHaveBeenCalled()
})

test('no hint when the investigation contributed', () => {
  render(<ScopeSwitch value="investigation" onChange={vi.fn()} />)
  expect(screen.queryByText(/contributed no facts/)).not.toBeInTheDocument()
})
