import { downloadFile, fileNameFromDisposition } from './download'
import { TOKEN_STORAGE_KEY } from './client'
import { mockApi } from '../test/utils'

let clicked: { href: string; download: string }[] = []

beforeEach(() => {
  clicked = []
  localStorage.clear()
  // jsdom has no object URLs: install stand-ins.
  URL.createObjectURL = vi.fn(() => 'blob:argus/1')
  URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    clicked.push({ href: this.href, download: this.download })
  })
})

afterEach(() => vi.restoreAllMocks())

test.each([
  ['attachment; filename="Scattered_Spider.stix.json"', 'Scattered_Spider.stix.json'],
  ['attachment; filename=plain.md', 'plain.md'],
  ["attachment; filename=\"fallback.md\"; filename*=UTF-8''caf%C3%A9.md", 'café.md'],
  ['attachment; filename="../../etc/passwd"', 'passwd'],
  ['attachment; filename="..\\\\evil.md"', 'evil.md'],
  ['attachment', null],
  ['attachment; filename=""', null],
])('fileNameFromDisposition(%s)', (header, expected) => {
  expect(fileNameFromDisposition(header)).toBe(expected)
})

test('fileNameFromDisposition without a header', () => {
  expect(fileNameFromDisposition(null)).toBeNull()
})

test('downloadFile fetches with the token, saves the blob under the server file name and revokes the URL', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout'] })
  onTestFinished(() => { vi.useRealTimers() })
  localStorage.setItem(TOKEN_STORAGE_KEY, 'tok-1')
  const fetchMock = mockApi({
    'GET /api/threats/x/export': new Response('{"type":"bundle"}', {
      headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="Spider.stix.json"' },
    }),
  })
  await downloadFile('/api/threats/x/export?format=stix', 'threat.stix.json')
  const [, init] = fetchMock.mock.calls[0]
  expect(new Headers(init?.headers).get('X-Argus-Token')).toBe('tok-1')
  expect(clicked).toEqual([{ href: 'blob:argus/1', download: 'Spider.stix.json' }])
  const blob = vi.mocked(URL.createObjectURL).mock.calls[0][0] as Blob
  expect(await blob.text()).toBe('{"type":"bundle"}')
  // Revoked only after a grace period: Firefox cancels a blob download whose URL is revoked right away.
  vi.advanceTimersByTime(9_999)
  expect(URL.revokeObjectURL).not.toHaveBeenCalled()
  vi.advanceTimersByTime(1)
  expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:argus/1')
  expect(document.querySelector('a[download]')).toBeNull() // the temporary link is gone
})

test('downloadFile falls back to the given name', async () => {
  mockApi({ 'GET /api/file': new Response('x') })
  await downloadFile('/api/file', 'threat.md')
  expect(clicked[0].download).toBe('threat.md')
})

test('downloadFile rejects with the server error and saves nothing', async () => {
  mockApi({ 'GET /api/file': new Response(JSON.stringify({ error: 'unknown threat' }), { status: 404 }) })
  await expect(downloadFile('/api/file', 'threat.md')).rejects.toMatchObject({ status: 404, message: 'unknown threat' })
  expect(clicked).toEqual([])
  expect(URL.createObjectURL).not.toHaveBeenCalled()
})
