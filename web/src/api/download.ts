import { apiRequest } from './client'

/** Base name only: a server-sent name must never steer the save into another folder. */
function baseName(name: string): string | null {
  const base = name.split(/[/\\]/).pop()?.trim() ?? ''
  return base && base !== '.' && base !== '..' ? base : null
}

/** The file name from a `Content-Disposition` header (`filename*=UTF-8''...` preferred over `filename=`), or null. */
export function fileNameFromDisposition(header: string | null): string | null {
  if (!header) return null
  const extended = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(header)
  if (extended) {
    try {
      const name = baseName(decodeURIComponent(extended[1].trim()))
      if (name) return name
    } catch {
      // malformed percent-encoding: fall back to the plain parameter
    }
  }
  const plain = /filename\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(header)
  return plain ? baseName(plain[1] ?? plain[2]) : null
}

/**
 * Download an API file. A plain download link cannot send the token header, so the file is fetched through the
 * API client, then saved through a temporary object URL. Rejects with an `ApiError` (nothing is saved) when the server
 * refuses, so a caller can show the error instead of saving an error body as the file.
 */
export async function downloadFile(path: string, fallbackName: string): Promise<void> {
  const response = await apiRequest(path)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileNameFromDisposition(response.headers.get('Content-Disposition')) ?? fallbackName
  link.style.display = 'none'
  document.body.appendChild(link)
  try {
    link.click()
  } finally {
    link.remove()
    // Revoked after a grace period: Firefox cancels a blob download whose URL is revoked right after the click.
    setTimeout(() => URL.revokeObjectURL(url), 10_000)
  }
}
