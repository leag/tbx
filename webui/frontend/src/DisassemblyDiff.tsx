import { useEffect, useMemo, useRef } from 'react'
import { diffInstructions } from './disassemblyDiff'
import type { DiffRow } from './disassemblyDiff'
import Disassembly, { buildLabels, buildStatementComments, withLabel } from './Disassembly'
import type { DisassemblySource } from './useDisassembly'
import { useDisassembly } from './useDisassembly'
import type { Instruction } from './api'

type Props = {
  originalSource: DisassemblySource
  recompiledSource: DisassemblySource
  highlightRange?: [number, number] | null
  statements: { address: number; text: string }[]
  // Reports the row-diff count up to the caller so it can be shown as a
  // full-width bar aligned with the hex dump above, instead of squeezed
  // into this panel's own (narrower, when hex is also shown) column.
  onStats?: (stats: { changed: number; total: number } | null) => void
}

function Cell({
  addr,
  text,
  tone,
  highlighted,
  label,
  targetLabel,
  onJump,
  comment,
  isFirst,
}: {
  addr?: string
  text: string
  tone?: 'added' | 'removed'
  highlighted?: boolean
  label?: string
  targetLabel?: string
  onJump?: () => void
  comment?: string | null
  isFirst?: boolean
}) {
  return (
    <div>
      {comment && (
        <div
          style={{
            color: 'var(--text-dim)',
            opacity: 0.9,
            marginTop: isFirst ? 0 : 10,
            whiteSpace: 'pre-wrap',
          }}
        >
          ; {comment}
        </div>
      )}
      {label && (
        <div style={{ color: 'var(--purple)', opacity: 0.8, marginTop: isFirst ? 0 : 6 }}>{label}:</div>
      )}
      <div
        style={{
          whiteSpace: 'pre',
          background: highlighted
            ? 'rgba(102, 217, 239, 0.25)'
            : tone === 'removed'
              ? 'rgba(249, 38, 114, 0.18)'
              : tone === 'added'
                ? 'rgba(166, 226, 46, 0.18)'
                : undefined,
          outline: highlighted ? '1px solid #66d9ef' : undefined,
        }}
      >
        {addr != null && <span style={{ opacity: 0.5 }}>{addr}</span>}
        {addr != null && '  '}
        <span style={{ color: 'var(--orange)' }}>{text}</span>
        {targetLabel && (
          <>
            {' '}
            <span
              role="button"
              title={`Jump to ${targetLabel}`}
              onClick={onJump}
              style={{ color: 'var(--cyan)', cursor: 'pointer', opacity: 0.8 }}
            >
              ↷
            </span>
          </>
        )}
      </div>
    </div>
  )
}

export default function DisassemblyDiff({
  originalSource,
  recompiledSource,
  highlightRange,
  statements,
  onStats,
}: Props) {
  const original = useDisassembly(originalSource)
  const recompiled = useDisassembly(recompiledSource)
  const leftRef = useRef<HTMLDivElement>(null)
  const rightRef = useRef<HTMLDivElement>(null)

  // undefined: not loaded yet; null: loaded but too big to diff.
  const rows = useMemo(
    () =>
      original.instructions && recompiled.instructions
        ? diffInstructions(original.instructions, recompiled.instructions)
        : undefined,
    [original.instructions, recompiled.instructions]
  )

  useEffect(() => {
    if (!onStats) return
    // Don't clear stats while a fresh disassembly is still loading (rows
    // === undefined) -- only report once the outcome is settled, so the
    // status bar doesn't flash the segment away and back on every reload.
    if (rows === undefined) return
    if (rows === null) {
      onStats(null)
      return
    }
    onStats({ changed: rows.filter((r) => r.kind !== 'same').length, total: rows.length })
  }, [rows, onStats])

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

  // Too many instructions to diff -- fall back to the two independent,
  // non-aligned panels (still with labels, statement comments, and
  // highlight support) rather than showing nothing.
  if (!rows) {
    return (
      <div>
        <p style={{ opacity: 0.6, fontSize: '12px', marginBottom: 8 }}>
          Too many instructions to diff ({original.instructions.length} vs {recompiled.instructions.length}) --
          showing both streams without alignment.
        </p>
        <div style={{ display: 'flex', gap: 16 }}>
          <Disassembly
            label="Original disassembly"
            source={originalSource}
            highlightRange={highlightRange}
            statements={statements}
          />
          <Disassembly
            label="Recompiled disassembly"
            source={recompiledSource}
            highlightRange={highlightRange}
            statements={statements}
          />
        </div>
      </div>
    )
  }

  const originalLabels = buildLabels(original.instructions)
  const recompiledLabels = buildLabels(recompiled.instructions)
  const originalComments = buildStatementComments(original.instructions, statements)
  const recompiledComments = buildStatementComments(recompiled.instructions, statements)
  const originalIndexByAddress = new Map(original.instructions.map((ins, i) => [ins.address, i]))
  const recompiledIndexByAddress = new Map(recompiled.instructions.map((ins, i) => [ins.address, i]))

  // Row index each address lands on, per column -- used both to scroll to
  // a highlightRange match and to jump to a clicked jump/call target.
  const leftRowForAddress = new Map<number, number>()
  const rightRowForAddress = new Map<number, number>()
  rows.forEach((row, i) => {
    if (row.kind !== 'added') leftRowForAddress.set(row.original.address, i)
    if (row.kind !== 'removed') rightRowForAddress.set(row.recompiled.address, i)
  })

  function jumpTo(target: number, side: 'left' | 'right') {
    const map = side === 'left' ? leftRowForAddress : rightRowForAddress
    const ref = side === 'left' ? leftRef : rightRef
    const index = map.get(target)
    if (index == null) return
    ref.current?.querySelector(`[data-row="${index}"]`)?.scrollIntoView({ block: 'center' })
  }

  return (
    <DisassemblyDiffBody
      rows={rows}
      leftRef={leftRef}
      rightRef={rightRef}
      syncScroll={syncScroll}
      highlightRange={highlightRange}
      originalLabels={originalLabels}
      recompiledLabels={recompiledLabels}
      originalComments={originalComments}
      recompiledComments={recompiledComments}
      originalIndexByAddress={originalIndexByAddress}
      recompiledIndexByAddress={recompiledIndexByAddress}
      jumpTo={jumpTo}
    />
  )
}

function DisassemblyDiffBody({
  rows,
  leftRef,
  rightRef,
  syncScroll,
  highlightRange,
  originalLabels,
  recompiledLabels,
  originalComments,
  recompiledComments,
  originalIndexByAddress,
  recompiledIndexByAddress,
  jumpTo,
}: {
  rows: DiffRow[]
  leftRef: React.RefObject<HTMLDivElement | null>
  rightRef: React.RefObject<HTMLDivElement | null>
  syncScroll: (top: number, from: 'left' | 'right') => void
  highlightRange?: [number, number] | null
  originalLabels: Map<number, string>
  recompiledLabels: Map<number, string>
  originalComments: (string | null)[]
  recompiledComments: (string | null)[]
  originalIndexByAddress: Map<number, number>
  recompiledIndexByAddress: Map<number, number>
  jumpTo: (target: number, side: 'left' | 'right') => void
}) {
  // Scroll the row containing the highlightRange into view whenever it
  // changes -- mirrors Disassembly.tsx's own effect, but a single row index
  // drives both synced columns here.
  useEffect(() => {
    if (!highlightRange) return
    const index = rows.findIndex((row) => {
      const addr =
        row.kind === 'added' ? row.recompiled.address : row.original.address
      return addr >= highlightRange[0] && addr < highlightRange[1]
    })
    if (index < 0) return
    leftRef.current?.querySelector(`[data-row="${index}"]`)?.scrollIntoView({ block: 'center' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightRange, rows])

  function inRange(addr: number | undefined): boolean {
    return !!highlightRange && addr != null && addr >= highlightRange[0] && addr < highlightRange[1]
  }

  return (
    <div>
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
            {rows.map((row, i) => {
              if (row.kind === 'added') return <div key={i} data-row={i} />
              const ins: Instruction = row.original
              const idx = originalIndexByAddress.get(ins.address)
              const label = originalLabels.get(ins.address)
              const targetLabel = ins.target != null ? originalLabels.get(ins.target) : undefined
              return (
                <div key={i} data-row={i}>
                  <Cell
                    addr={ins.address.toString(16).padStart(6, '0')}
                    text={withLabel(ins.text, targetLabel)}
                    tone={row.kind === 'removed' ? 'removed' : undefined}
                    highlighted={inRange(ins.address)}
                    label={label}
                    targetLabel={targetLabel}
                    onJump={() => jumpTo(ins.target as number, 'left')}
                    comment={idx != null ? originalComments[idx] : null}
                    isFirst={i === 0}
                  />
                </div>
              )
            })}
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
            {rows.map((row, i) => {
              if (row.kind === 'removed') return <div key={i} data-row={i} />
              const ins: Instruction = row.recompiled
              const idx = recompiledIndexByAddress.get(ins.address)
              const label = recompiledLabels.get(ins.address)
              const targetLabel = ins.target != null ? recompiledLabels.get(ins.target) : undefined
              return (
                <div key={i} data-row={i}>
                  <Cell
                    addr={ins.address.toString(16).padStart(6, '0')}
                    text={withLabel(ins.text, targetLabel)}
                    tone={row.kind === 'added' ? 'added' : undefined}
                    highlighted={inRange(ins.address)}
                    label={label}
                    targetLabel={targetLabel}
                    onJump={() => jumpTo(ins.target as number, 'right')}
                    comment={idx != null ? recompiledComments[idx] : null}
                    isFirst={i === 0}
                  />
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
