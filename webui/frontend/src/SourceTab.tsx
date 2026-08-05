import { useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { recompile } from './api'
import type { RecompileResult } from './api'

type Props = {
  sessionId: string
  initialSource: string
}

export default function SourceTab({ sessionId, initialSource }: Props) {
  const [source, setSource] = useState(initialSource)
  const [result, setResult] = useState<RecompileResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleRecompile() {
    setError(null)
    setResult(null)
    try {
      setResult(await recompile(sessionId, source))
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div>
      <div aria-label="source editor">
        <CodeMirror value={source} height="600px" onChange={(value) => setSource(value)} />
      </div>
      <button onClick={handleRecompile}>Recompile</button>
      {result && (
        <div>
          <p>Match: {(result.ratio * 100).toFixed(2)}%</p>
          {!result.matched && <p>First diff at offset {result.first_diff_offset}</p>}
        </div>
      )}
      {error && <p role="alert">{error}</p>}
    </div>
  )
}
