import { useEffect, useId, useRef, useState, type DragEvent } from 'react'

/**
 * Drop files here, or click to pick them.
 *
 * A bare `<input type="file">` is a correct control that nobody reads as an invitation. Argus
 * asks the operator to hand over documents in two places now — bulk ingest, and repairing a
 * document a publisher refuses to serve — so the invitation is worth making legible.
 *
 * The real input stays in the DOM and keeps the label association, so keyboard and screen-reader
 * users get the ordinary file-picker behaviour; the drop target is additive. Drag state is per
 * instance, and `dragDepth` counts enter/leave pairs because dragging over a child element fires
 * `dragleave` on the parent — tracking a boolean makes the highlight flicker.
 */
export function FileDropZone({
  onFiles, accept, multiple = false, disabled = false, label, hint, selected = [],
}: {
  onFiles: (files: File[]) => void
  accept?: string
  multiple?: boolean
  disabled?: boolean
  /** What the operator is being asked for. Shown as the clickable text. */
  label: string
  /** One line under it: formats, limits, what happens next. */
  hint?: string
  /** Files already chosen, listed back so the operator can see what they picked. */
  selected?: File[]
}) {
  const input = useRef<HTMLInputElement>(null)
  const inputId = useId()
  const [dragDepth, setDragDepth] = useState(0)
  const dragging = dragDepth > 0

  // When the parent clears its selection — it submitted, or the operator cancelled — the native
  // input has to be cleared too. Otherwise it keeps the FileList, picking the same file again
  // fires no `change` event, and the form only looks ready for the next one.
  const selectedCount = selected.length
  useEffect(() => {
    if (selectedCount === 0) resetFileInput(input.current)
  }, [selectedCount])

  const take = (files: FileList | null) => {
    if (disabled) return
    const picked = Array.from(files ?? [])
    if (picked.length) onFiles(multiple ? picked : picked.slice(0, 1))
  }

  const stop = (event: DragEvent) => {
    event.preventDefault()
    event.stopPropagation()
  }

  return (
    <div
      onDragEnter={(event) => { stop(event); setDragDepth((depth) => depth + 1) }}
      onDragLeave={(event) => { stop(event); setDragDepth((depth) => Math.max(0, depth - 1)) }}
      onDragOver={stop}
      onDrop={(event) => { stop(event); setDragDepth(0); take(event.dataTransfer?.files ?? null) }}
      className={`rounded border border-dashed p-4 text-center transition-colors ${
        disabled ? 'border-gray-700 opacity-60'
          : dragging ? 'border-cyan-400 bg-cyan-400/5' : 'border-gray-600 hover:border-gray-500'
      }`}
    >
      <input ref={input} id={inputId} type="file" multiple={multiple} accept={accept} disabled={disabled}
        className="sr-only"
        onChange={(event) => take(event.target.files)} />
      <label htmlFor={inputId} className={disabled ? 'text-sm text-gray-500' : 'text-sm text-cyan-400 cursor-pointer hover:underline underline-offset-2'}>
        {label}
      </label>
      <span className="text-sm text-gray-500"> or drop {multiple ? 'files' : 'a file'} here</span>
      {hint && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
      {selected.length > 0 && (
        <ul className="mt-3 space-y-0.5 text-left">
          {selected.map((file) => (
            <li key={file.name} className="text-xs text-gray-300 font-mono truncate">{file.name}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** Clear a file input's value, so picking the same file twice in a row still fires `change`. */
export function resetFileInput(element: HTMLInputElement | null): void {
  if (element) element.value = ''
}
