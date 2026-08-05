import { useState } from 'react'
import UploadZone from './UploadZone'
import SourceTab from './SourceTab'
import IrTab from './IrTab'
import { decompile } from './api'
import type { DecompileResult } from './api'

export default function App() {
  const [decompiled, setDecompiled] = useState<DecompileResult | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'source' | 'ir'>('source')

  async function handleFile(file: File) {
    setUploadError(null)
    try {
      setDecompiled(await decompile(file))
      setActiveTab('source')
    } catch (e) {
      setUploadError((e as Error).message)
    }
  }

  return (
    <div>
      <UploadZone onFileSelected={handleFile} />
      {uploadError && <p role="alert">{uploadError}</p>}
      {decompiled && (
        <div>
          <div role="tablist">
            <button role="tab" aria-selected={activeTab === 'source'} onClick={() => setActiveTab('source')}>
              Source
            </button>
            <button role="tab" aria-selected={activeTab === 'ir'} onClick={() => setActiveTab('ir')}>
              IR
            </button>
          </div>
          {activeTab === 'source' && (
            <SourceTab sessionId={decompiled.session_id} initialSource={decompiled.source} />
          )}
          {activeTab === 'ir' && <IrTab nodes={decompiled.ir} />}
        </div>
      )}
    </div>
  )
}
