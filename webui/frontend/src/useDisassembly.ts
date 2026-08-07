import { useEffect, useState } from 'react'
import { disassemble, disassembleBytes } from './api'
import type { Instruction } from './api'

// Either the original exe (fetched server-side by session) or the
// recompiled bytes (which only ever exist client-side, already sent down
// in the recompile response -- there's no session for them to disassemble
// by id).
export type DisassemblySource = { kind: 'session'; sessionId: string } | { kind: 'bytes'; dataB64: string }

export function useDisassembly(source: DisassemblySource): {
  instructions: Instruction[] | null
  error: string | null
} {
  const [instructions, setInstructions] = useState<Instruction[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  // One string key per distinct source so the fetch effect below re-runs
  // exactly when what to disassemble actually changes (a fresh session, or
  // a new recompile's bytes) -- not on every re-render, which a plain
  // object in the dependency array would trigger every time.
  const sourceKey = source.kind === 'session' ? `session:${source.sessionId}` : `bytes:${source.dataB64}`

  useEffect(() => {
    setInstructions(null)
    setError(null)
    const request = source.kind === 'session' ? disassemble(source.sessionId) : disassembleBytes(source.dataB64)
    request.then(setInstructions).catch((e) => setError((e as Error).message))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceKey])

  return { instructions, error }
}
