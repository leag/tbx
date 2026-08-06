import { useEffect, useMemo, useRef } from 'react'

type Props = {
  originalB64: string
  recompiledB64: string
  firstDiffOffset: number | null
  // Byte range in the ORIGINAL binary that the currently focused source
  // line decoded from. There's no real mapping into the recompiled bytes
  // (the real compiler is opaque), but the same range is applied to the
  // Recompiled column too as a best-effort: wherever the two binaries are
  // still byte-identical (everywhere before firstDiffOffset, which is
  // everywhere when matched), the same offset is the same content.
  highlightRange?: [number, number] | null
}

function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function hex(byte: number): string {
  return byte.toString(16).padStart(2, '0')
}

function printable(byte: number): string {
  return byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.'
}

function HexColumn({
  label,
  bytes,
  otherBytes,
  scrollRef,
  onScroll,
  highlightRange,
}: {
  label: string
  bytes: Uint8Array
  otherBytes: Uint8Array
  scrollRef: React.RefObject<HTMLDivElement | null>
  onScroll: (top: number) => void
  highlightRange?: [number, number] | null
}) {
  const rowCount = Math.ceil(bytes.length / 16)
  const rows = []
  for (let row = 0; row < rowCount; row++) {
    const offset = row * 16
    const cells = []
    for (let col = 0; col < 16; col++) {
      const i = offset + col
      if (i >= bytes.length) {
        cells.push(
          <span key={col} style={{ display: 'inline-block', width: '1.6em' }} />
        )
        continue
      }
      const b = bytes[i]
      const mismatch = i >= otherBytes.length || otherBytes[i] !== b
      const highlighted = !!highlightRange && i >= highlightRange[0] && i < highlightRange[1]
      cells.push(
        <span
          key={col}
          style={{
            display: 'inline-block',
            width: '1.6em',
            color: mismatch ? '#f92672' : undefined,
            fontWeight: mismatch || highlighted ? 'bold' : undefined,
            background: mismatch
              ? 'rgba(249, 38, 114, 0.18)'
              : highlighted
                ? 'rgba(102, 217, 239, 0.25)'
                : undefined,
            outline: highlighted ? '1px solid #66d9ef' : undefined,
          }}
        >
          {hex(b)}
        </span>
      )
    }
    const ascii = Array.from({ length: 16 }, (_, col) => {
      const i = offset + col
      if (i >= bytes.length) return ' '
      return printable(bytes[i])
    }).join('')
    rows.push(
      <div key={row} data-row={row} style={{ whiteSpace: 'pre' }}>
        <span style={{ opacity: 0.5 }}>{offset.toString(16).padStart(6, '0')}</span>{'  '}
        {cells}
        {'  '}
        <span style={{ opacity: 0.7 }}>{ascii}</span>
      </div>
    )
  }

  return (
    <div className="panel" style={{ flex: 1, minWidth: 0 }}>
      <h4 style={{ margin: 0, padding: '8px 10px', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {label} ({bytes.length} bytes)
      </h4>
      <div
        ref={scrollRef}
        onScroll={(e) => onScroll(e.currentTarget.scrollTop)}
        style={{
          fontFamily: 'var(--mono)',
          fontSize: '12.5px',
          height: '500px',
          overflow: 'auto',
          overflowAnchor: 'none',
          padding: '6px 10px',
        }}
      >
        {rows}
      </div>
    </div>
  )
}

// Scroll a specific row into view by querying the DOM for it directly
// (via the `data-row` attribute every row carries) and using the browser's
// own scrollIntoView, rather than computing a pixel offset from an assumed
// row height -- the assumed-height approach landed at the wrong position
// in practice (rendered row height didn't match the assumption).
function scrollRowIntoView(container: HTMLDivElement | null, row: number) {
  const target = container?.querySelector(`[data-row="${row}"]`)
  target?.scrollIntoView({ block: 'center' })
}

export default function BinaryDiff({
  originalB64,
  recompiledB64,
  firstDiffOffset,
  highlightRange,
}: Props) {
  const original = useMemo(() => decodeBase64(originalB64), [originalB64])
  const recompiled = useMemo(() => decodeBase64(recompiledB64), [recompiledB64])
  const leftRef = useRef<HTMLDivElement>(null)
  const rightRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (firstDiffOffset == null) return
    const row = Math.floor(firstDiffOffset / 16)
    scrollRowIntoView(leftRef.current, row)
    scrollRowIntoView(rightRef.current, row)
  }, [firstDiffOffset, originalB64, recompiledB64])

  useEffect(() => {
    if (!highlightRange) return
    const row = Math.floor(highlightRange[0] / 16)
    scrollRowIntoView(leftRef.current, row)
    scrollRowIntoView(rightRef.current, row)
  }, [highlightRange])

  function syncScroll(top: number, from: 'left' | 'right') {
    const target = from === 'left' ? rightRef.current : leftRef.current
    if (target && target.scrollTop !== top) target.scrollTop = top
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 16 }}>
        <HexColumn
          label="Original"
          bytes={original}
          otherBytes={recompiled}
          scrollRef={leftRef}
          onScroll={(top) => syncScroll(top, 'left')}
          highlightRange={highlightRange}
        />
        <HexColumn
          label="Recompiled"
          bytes={recompiled}
          otherBytes={original}
          scrollRef={rightRef}
          onScroll={(top) => syncScroll(top, 'right')}
          highlightRange={highlightRange}
        />
      </div>
    </div>
  )
}
