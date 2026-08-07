import { useMemo, useState } from 'react'
import UploadZone from './UploadZone'
import EditTab from './EditTab'
import CompareTab from './CompareTab'
import IrTab from './IrTab'
import { decompile } from './api'
import type { DecompileResult, RecompileResult } from './api'

type View = 'workspace' | 'ir'

// Pairs each top-level statement's byte offset with its actual source line,
// via the backend's authoritative `line_starts` (index i -> 0-based line
// number in `source`). Deliberately not re-derived by counting lines that
// look numbered: a statement doesn't always emit exactly one of those (an
// IF/END IF or SUB/END SUB block spans several with only the head numbered;
// grouped statements like "10 A=1:B=2" share one) -- counting broke this
// exact way on tbd73.exe, where 70 top-level statements produced 97
// digit-prefixed lines.
function buildStatementMarkers(
  source: string,
  addresses: (number | null)[],
  lineStarts: number[]
): { address: number; text: string }[] {
  const lines = source.split('\n')
  const markers: { address: number; text: string }[] = []
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    if (address == null) continue
    const text = lines[lineStarts[i]]
    if (text != null) markers.push({ address, text: text.trim() })
  }
  return markers
}

export default function App() {
  const [decompiled, setDecompiled] = useState<DecompileResult | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [activeView, setActiveView] = useState<View>('workspace')
  const [recompileResult, setRecompileResult] = useState<RecompileResult | null>(null)
  const [highlightRange, setHighlightRange] = useState<[number, number] | null>(null)
  const statements = useMemo(
    () =>
      decompiled
        ? buildStatementMarkers(decompiled.source, decompiled.addresses, decompiled.line_starts)
        : [],
    [decompiled]
  )

  async function handleFile(file: File) {
    setUploadError(null)
    try {
      setDecompiled(await decompile(file))
      setRecompileResult(null)
      setHighlightRange(null)
      setActiveView('workspace')
    } catch (e) {
      setUploadError((e as Error).message)
    }
  }

  return (
    <div>
      <h1>⚙️ tbx</h1>
      <UploadZone onFileSelected={handleFile} />
      {uploadError && <p role="alert">{uploadError}</p>}
      {decompiled && (
        <div>
          <div role="tablist">
            <button role="tab" aria-selected={activeView === 'workspace'} onClick={() => setActiveView('workspace')}>
              Edit &amp; Compare
            </button>
            <button role="tab" aria-selected={activeView === 'ir'} onClick={() => setActiveView('ir')}>
              IR
            </button>
          </div>
          {/* Edit and Compare render side by side (not as separate tabs) so
              the recompiled binary is visible right next to the source that
              produced it -- no need to switch away from the editor to see
              a comparison, and the source-line highlight lands somewhere
              already on screen. Kept mounted (display:none, not unmounted)
              under the IR view too, so editor/cursor state survives. */}
          <div style={{ display: activeView === 'workspace' ? 'flex' : 'none', gap: 16 }}>
            <div style={{ flex: '1 1 35%', minWidth: 0 }}>
              <EditTab
                // Force a remount on every new upload: EditTab seeds its
                // local source/dialect/toggles state from props only once
                // (via useState(initialSource)), so without a key change
                // React reuses the old instance and keeps showing the
                // previous file's source after a second upload.
                key={decompiled.session_id}
                sessionId={decompiled.session_id}
                initialSource={decompiled.source}
                detectedDialect={decompiled.dialect}
                detectedToggles={decompiled.toggles}
                addresses={decompiled.addresses}
                lineStarts={decompiled.line_starts}
                onRecompiled={setRecompileResult}
                onHighlightRange={setHighlightRange}
              />
            </div>
            <div style={{ flex: '1 1 65%', minWidth: 0 }}>
              <CompareTab
                sessionId={decompiled.session_id}
                result={recompileResult}
                highlightRange={highlightRange}
                statements={statements}
              />
            </div>
          </div>
          {activeView === 'ir' && <IrTab nodes={decompiled.ir} />}
        </div>
      )}
    </div>
  )
}
