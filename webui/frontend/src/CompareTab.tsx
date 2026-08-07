import { useState } from 'react'
import BinaryDiff from './BinaryDiff'
import DisassemblyDiff from './DisassemblyDiff'
import type { RecompileResult } from './api'

type Props = {
  sessionId: string
  result: RecompileResult | null
  highlightRange?: [number, number] | null
  statements: { address: number; text: string }[]
}

type View = 'both' | 'hex' | 'disasm'

const VIEW_OPTIONS: { key: View; label: string }[] = [
  { key: 'both', label: 'Hex + Disassembly' },
  { key: 'hex', label: 'Hex only' },
  { key: 'disasm', label: 'Disassembly' },
]

// Small pie-chart glyph for the match ratio: a conic-gradient circle is
// the cheapest way to draw a filled wedge without pulling in a chart lib
// for a single stat this size.
function MatchPie({ ratio }: { ratio: number }) {
  const pct = Math.max(0, Math.min(1, ratio)) * 100
  return (
    <span
      title={`${pct.toFixed(2)}% match`}
      style={{
        display: 'inline-block',
        width: 12,
        height: 12,
        borderRadius: '50%',
        marginRight: 5,
        verticalAlign: 'middle',
        background: `conic-gradient(var(--green, #a6e22e) ${pct}%, var(--border) ${pct}% 100%)`,
      }}
    />
  )
}

export default function CompareTab({ sessionId, result, highlightRange, statements }: Props) {
  const [view, setView] = useState<View>('both')
  const [diffStats, setDiffStats] = useState<{ changed: number; total: number } | null>(null)

  if (!result) {
    return <p>Recompile from the Edit tab to see a comparison here.</p>
  }

  const showHex = view === 'both' || view === 'hex'
  const showDisasm = view === 'both' || view === 'disasm'
  // Widen whichever side is shown alone; when both show, hex gets less
  // room since the disassembly pane already covers a lot of width.
  const hexFlex = view === 'hex' ? '1 1 100%' : '1 1 40%'
  const disasmFlex = view === 'disasm' ? '1 1 100%' : '1 1 60%'

  return (
    <div>
      <div role="tablist" style={{ marginBottom: 12 }}>
        {VIEW_OPTIONS.map((opt) => (
          <button
            key={opt.key}
            role="tab"
            aria-selected={view === opt.key}
            onClick={() => setView(opt.key)}
          >
            {opt.label}
          </button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16 }}>
        {showHex && (
          <div style={{ flex: hexFlex, minWidth: 0 }}>
            <BinaryDiff
              originalB64={result.original_b64}
              recompiledB64={result.recompiled_b64}
              firstDiffOffset={result.first_diff_offset}
              highlightRange={highlightRange}
            />
          </div>
        )}
        {showDisasm && (
          <div style={{ flex: disasmFlex, minWidth: 0 }}>
            <DisassemblyDiff
              originalSource={{ kind: 'session', sessionId }}
              recompiledSource={{ kind: 'bytes', dataB64: result.recompiled_b64 }}
              highlightRange={highlightRange}
              statements={statements}
              onStats={setDiffStats}
            />
          </div>
        )}
      </div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          gap: 16,
          marginTop: 10,
          padding: '6px 10px',
          fontSize: '12px',
          color: 'var(--text-dim)',
          background: 'var(--panel)',
          border: '1px solid var(--border)',
          borderRadius: 6,
        }}
      >
        <span>
          <MatchPie ratio={result.ratio} />
          Match: <strong style={{ color: 'var(--text-h)' }}>{(result.ratio * 100).toFixed(2)}%</strong>
          {showHex && !result.matched && ` | first diff at offset ${result.first_diff_offset}`}
          {showDisasm && diffStats && (
            <>
              {' | '}
              {diffStats.changed === 0
                ? 'Identical instruction streams'
                : `${diffStats.changed} of ${diffStats.total} rows differ`}
            </>
          )}
        </span>
        <span>Click a line in the editor to highlight where it decoded from in the original binary.</span>
      </div>
    </div>
  )
}
