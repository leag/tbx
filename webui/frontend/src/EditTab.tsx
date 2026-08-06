import { useEffect, useRef, useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { monokai } from '@uiw/codemirror-theme-monokai'
import type { ViewUpdate } from '@codemirror/view'
import { listDialects, listToggles, recompile } from './api'
import type { RecompileResult, ToggleInfo } from './api'
import { basicLanguage } from './basicLanguage'

type Props = {
  sessionId: string
  initialSource: string
  detectedDialect: string
  detectedToggles?: string
  addresses: (number | null)[]
  lineStarts: number[]
  onRecompiled: (result: RecompileResult) => void
  onHighlightRange: (range: [number, number] | null) => void
}

// Whimsical touch: each IDE Options toggle gets a small emoji so the
// checkbox row is friendlier than a wall of technical letters.
const TOGGLE_EMOJI: Record<string, string> = {
  '8': '\u{1F9EE}', // 8087 required -- abacus/coprocessor math
  K: '⌨️', // Keyboard break
  B: '\u{1F4CF}', // Bounds -- measuring tape
  O: '\u{1F4A5}', // Overflow -- boom
  S: '\u{1F95E}', // Stack test -- a stack of pancakes
}

// The top-level statement whose text `cursorLine` (1-based, CodeMirror's
// convention) falls inside, via the backend's authoritative `lineStarts`
// (index i -> 0-based line that statement's text starts at, non-decreasing).
// A line inside a SUB/IF/DO body that isn't itself a top-level statement's
// first line resolves to the enclosing one, same as any line strictly
// between one entry and the next. Best-effort once the source has been
// edited (lineStarts describes the ORIGINAL decompiled text, and tbx has no
// mapping into the recompiled binary at all besides), but exact against the
// unedited source -- unlike counting lines that look numbered, which breaks
// whenever a statement doesn't emit exactly one of those (tbd73.exe).
function statementIndexForLine(lineStarts: number[], cursorLine: number): number {
  const zeroBased = cursorLine - 1
  let index = -1
  for (let i = 0; i < lineStarts.length && lineStarts[i] <= zeroBased; i++) {
    index = i
  }
  return index
}

export default function EditTab({
  sessionId,
  initialSource,
  detectedDialect,
  detectedToggles,
  addresses = [],
  lineStarts,
  onRecompiled,
  onHighlightRange,
}: Props) {
  const [source, setSource] = useState(initialSource)
  const [error, setError] = useState<string | null>(null)
  const [dialect, setDialect] = useState(detectedDialect)
  const [availableDialects, setAvailableDialects] = useState<string[]>([detectedDialect])
  const [toggles, setToggles] = useState(detectedToggles ?? '')
  const [availableToggles, setAvailableToggles] = useState<ToggleInfo[]>([])
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    listDialects()
      .then((dialects) => {
        if (Array.isArray(dialects) && dialects.length > 0) setAvailableDialects(dialects)
      })
      .catch(() => {
        // Keep the detected-dialect-only fallback; the recompile call will
        // surface any real problem (e.g. the oracle not being configured).
      })
    listToggles()
      .then((entries) => {
        if (Array.isArray(entries)) setAvailableToggles(entries)
      })
      .catch(() => {
        // No toggle checkboxes shown; the auto-detected toggles still apply.
      })
  }, [])

  function toggleLetter(letter: string, checked: boolean) {
    setToggles((prev) => {
      const set = new Set(prev)
      if (checked) set.add(letter)
      else set.delete(letter)
      return availableToggles.map((t) => t.letter).filter((l) => set.has(l)).join('')
    })
  }

  const lastRangeRef = useRef<[number, number] | null>(null)

  function handleCursorUpdate(update: ViewUpdate) {
    // `selectionSet`/`docChanged` are unreliable for a plain mouse click
    // (verified empirically: both come back false on a click that visibly
    // moves the cursor) -- CodeMirror still gives every onUpdate call the
    // current state regardless, so just recompute unconditionally. Cheap:
    // this is a handful of array scans over already-short source text.
    //
    // Emitting a new range object on every one of those ticks (cursor
    // blink, viewport measurement, etc.) still matters, though: consumers
    // key a useEffect off this value by reference, and a fresh array every
    // tick reruns their scrollIntoView forever, fighting anything else that
    // tries to scroll the same panel (e.g. a disassembly jump-to-label
    // click). Only call back when the resolved range actually changed.
    const safeAddresses = addresses ?? []
    const pos = update.state.selection.main.head
    const line = update.state.doc.lineAt(pos).number
    const index = statementIndexForLine(lineStarts, line)
    const start = index >= 0 && index < safeAddresses.length ? safeAddresses[index] : null
    let range: [number, number] | null = null
    if (start != null) {
      // End of the highlight range is the next statement's known start
      // address; if none follows (e.g. the last statement, or a run of
      // codeless statements after it), fall back to a 1-byte marker rather
      // than guessing how far the real range extends.
      let end: number | null = null
      for (let j = index + 1; j < safeAddresses.length; j++) {
        if (safeAddresses[j] != null) {
          end = safeAddresses[j]
          break
        }
      }
      range = [start, end ?? start + 1]
    }
    const prev = lastRangeRef.current
    const unchanged = prev === range || (prev && range && prev[0] === range[0] && prev[1] === range[1])
    if (unchanged) return
    lastRangeRef.current = range
    onHighlightRange(range)
  }

  async function handleRecompile() {
    setError(null)
    setBusy(true)
    try {
      onRecompiled(await recompile(sessionId, source, dialect, toggles))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div aria-label="source editor" className="panel" style={{ textAlign: 'left', marginBottom: 14 }}>
        <CodeMirror
          value={source}
          height="600px"
          theme={monokai}
          extensions={[basicLanguage]}
          onChange={(value) => setSource(value)}
          onUpdate={handleCursorUpdate}
        />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <label htmlFor="dialect-select" style={{ color: 'var(--text-dim)' }}>
          🎛️ Turbo Basic version
        </label>
        <select id="dialect-select" value={dialect} onChange={(e) => setDialect(e.target.value)}>
          {availableDialects.map((d) => (
            <option key={d} value={d}>
              {d}
              {d === detectedDialect ? ' (detected)' : ''}
            </option>
          ))}
        </select>
      </div>
      {availableToggles.length > 0 && (
        <fieldset>
          <legend>IDE Options toggles</legend>
          {availableToggles.map((t) => (
            <label key={t.letter} style={{ display: 'inline-block', marginRight: 16 }}>
              <input
                type="checkbox"
                checked={toggles.includes(t.letter)}
                onChange={(e) => toggleLetter(t.letter, e.target.checked)}
              />
              {' '}
              {TOGGLE_EMOJI[t.letter] ?? ''} {t.name}
              {detectedToggles?.includes(t.letter) ? ' (detected)' : ''}
            </label>
          ))}
        </fieldset>
      )}
      <button onClick={handleRecompile} disabled={busy}>
        {busy ? '⏳ Recompiling…' : '⚡ Recompile'}
      </button>
      {error && <p role="alert">{error}</p>}
    </div>
  )
}
