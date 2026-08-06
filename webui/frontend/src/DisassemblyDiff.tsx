import { useRef } from 'react'
import { diffInstructions } from './disassemblyDiff'
import type { DisassemblySource } from './useDisassembly'
import { useDisassembly } from './useDisassembly'

type Props = {
  originalSource: DisassemblySource
  recompiledSource: DisassemblySource
}

function Cell({ text, tone }: { text: string; tone?: 'added' | 'removed' }) {
  return (
    <div
      style={{
        whiteSpace: 'pre',
        background:
          tone === 'removed'
            ? 'rgba(249, 38, 114, 0.18)'
            : tone === 'added'
              ? 'rgba(166, 226, 46, 0.18)'
              : undefined,
      }}
    >
      {text}
    </div>
  )
}

export default function DisassemblyDiff({ originalSource, recompiledSource }: Props) {
  const original = useDisassembly(originalSource)
  const recompiled = useDisassembly(recompiledSource)
  const leftRef = useRef<HTMLDivElement>(null)
  const rightRef = useRef<HTMLDivElement>(null)

  function syncScroll(top: number, from: 'left' | 'right') {
    const target = from === 'left' ? rightRef.current : leftRef.current
    if (target && target.scrollTop !== top) target.scrollTop = top
  }

  if (original.error || recompiled.error) {
    return (
      <p style={{ opacity: 0.6, fontSize: '12px' }}>
        Disassembly unavailable: {original.error ?? recompiled.error}
      </p>
    )
  }
  if (!original.instructions || !recompiled.instructions) {
    return <p>Disassembling…</p>
  }

  const rows = diffInstructions(original.instructions, recompiled.instructions)
  if (!rows) {
    return (
      <p style={{ opacity: 0.6, fontSize: '12px' }}>
        Too many instructions to diff ({original.instructions.length} vs {recompiled.instructions.length}).
      </p>
    )
  }

  const changed = rows.filter((r) => r.kind !== 'same').length

  return (
    <div>
      <p style={{ fontSize: '12px', opacity: 0.6, marginBottom: 8 }}>
        {changed === 0 ? 'Identical instruction streams.' : `${changed} of ${rows.length} rows differ.`}
      </p>
      <div style={{ display: 'flex', gap: 16 }}>
        <div className="panel" style={{ flex: 1, minWidth: 0 }}>
          <h4 style={{ margin: 0, padding: '8px 10px', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            Original
          </h4>
          <div
            ref={leftRef}
            onScroll={(e) => syncScroll(e.currentTarget.scrollTop, 'left')}
            style={{
              fontFamily: 'var(--mono)',
              fontSize: '12.5px',
              height: '500px',
              overflow: 'auto',
              overflowAnchor: 'none',
              padding: '6px 10px',
            }}
          >
            {rows.map((row, i) =>
              row.kind === 'added' ? (
                <Cell key={i} text="" />
              ) : (
                <Cell
                  key={i}
                  text={`${row.original.address.toString(16).padStart(6, '0')}  ${row.original.text}`}
                  tone={row.kind === 'removed' ? 'removed' : undefined}
                />
              )
            )}
          </div>
        </div>
        <div className="panel" style={{ flex: 1, minWidth: 0 }}>
          <h4 style={{ margin: 0, padding: '8px 10px', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            Recompiled
          </h4>
          <div
            ref={rightRef}
            onScroll={(e) => syncScroll(e.currentTarget.scrollTop, 'right')}
            style={{
              fontFamily: 'var(--mono)',
              fontSize: '12.5px',
              height: '500px',
              overflow: 'auto',
              overflowAnchor: 'none',
              padding: '6px 10px',
            }}
          >
            {rows.map((row, i) =>
              row.kind === 'removed' ? (
                <Cell key={i} text="" />
              ) : (
                <Cell
                  key={i}
                  text={`${row.recompiled.address.toString(16).padStart(6, '0')}  ${row.recompiled.text}`}
                  tone={row.kind === 'added' ? 'added' : undefined}
                />
              )
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
