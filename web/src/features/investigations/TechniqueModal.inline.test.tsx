import { render } from '@testing-library/react'
import { renderInline } from './TechniqueModal'

test('renders <code> and backtick spans as monospace code', () => {
  const { container } = render(
    <div>{renderInline('Use <code>CreateKeyPair</code> or `sts:GetFederationToken` now.')}</div>,
  )
  const codes = container.querySelectorAll('code')
  expect(codes).toHaveLength(2)
  expect(codes[0].textContent).toBe('CreateKeyPair')
  expect(codes[1].textContent).toBe('sts:GetFederationToken')
})

test('renders [text](url) as a safe new-tab link', () => {
  const { container } = render(
    <div>{renderInline('see [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) for more')}</div>,
  )
  const a = container.querySelector('a')
  expect(a?.getAttribute('href')).toBe('https://attack.mitre.org/techniques/T1078/004')
  expect(a?.textContent).toBe('Cloud Accounts')
  expect(a?.getAttribute('rel')).toBe('noopener noreferrer')
})

test('does not linkify a non-http url: javascript: stays literal text', () => {
  const { container } = render(<div>{renderInline('click [x](javascript:alert(1))')}</div>)
  expect(container.querySelector('a')).toBeNull()
  expect(container.textContent).toContain('[x](javascript:alert(1))')
})
