import { useState } from 'react'
import BinaryDiff from './BinaryDiff'
import Disassembly from './Disassembly'
import DisassemblyDiff from './DisassemblyDiff'
import type { RecompileResult } from './api'

type Props = {
  sessionId: string
  result: RecompileResult | null
  highlightRange?: [number, number] | null
  statements: { address: number; text: string }[]
}

type View = 'both' | 'hex' | 'disasm' | 'diff'

const VIEW_OPTIONS: { key: View; label: string }[] = [
  { key: 'both', label: 'Hex + Disassembly' },
  { key: 'hex', label: 'Hex only' },
  { key: 'disasm', label: 'Disassembly only' },
  { key: 'diff', label: 'Disassembly diff' },
]

export default function CompareTab({ sessionId, result, highlightRange, statements }: Props) {
  const [view, setView] = useState<View>('both')

  if (!result) {
    return <p>Recompile from the Edit tab to see a comparison here.</p>
  }

  const showHex = view === 'both' || view === 'hex'
  const showDisasm = view === 'both' || view === 'disasm'
  const showDiff = view === 'diff'
  // Widen whichever side is shown alone; when both show, hex gets less
  // room since two disassembly panes already cover a lot of width.
  const hexFlex = view === 'hex' ? '1 1 100%' : '1 1 40%'
  const disasmFlex = view === 'disasm' ? '1 1 50%' : '1 1 30%'

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
          <>
            <div style={{ flex: disasmFlex, minWidth: 0 }}>
              <Disassembly
                label="Original disassembly"
                source={{ kind: 'session', sessionId }}
                highlightRange={highlightRange}
                statements={statements}
              />
            </div>
            <div style={{ flex: disasmFlex, minWidth: 0 }}>
              <Disassembly
                label="Recompiled disassembly"
                source={{ kind: 'bytes', dataB64: result.recompiled_b64 }}
                highlightRange={highlightRange}
                statements={statements}
              />
            </div>
          </>
        )}
        {showDiff && (
          <div style={{ flex: '1 1 100%', minWidth: 0 }}>
            <DisassemblyDiff
              originalSource={{ kind: 'session', sessionId }}
              recompiledSource={{ kind: 'bytes', dataB64: result.recompiled_b64 }}
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
          Match: <strong style={{ color: 'var(--text-h)' }}>{(result.ratio * 100).toFixed(2)}%</strong>
          {!result.matched && ` -- first diff at offset ${result.first_diff_offset}`}
        </span>
        <span>Click a line in the editor to highlight where it decoded from in the original binary.</span>
      </div>
    </div>
  )
}
