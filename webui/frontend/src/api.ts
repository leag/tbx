export type ApiError = { error: string }

export type IrNode = {
  type: string
  fields: Record<string, unknown>
  children: IrChild[]
}

export type IrChild =
  | { name: string; node: IrNode }
  | { name: string; nodes: IrNode[] }

export type DecompileResult = {
  session_id: string
  dialect: string
  toggles: string
  source: string
  ir: IrNode[]
  // One entry per top-level statement (same order as `ir`): the byte
  // offset that statement decoded from in the ORIGINAL exe, or null for a
  // codeless statement. No equivalent exists for the recompiled bytes.
  addresses: (number | null)[]
  // Same order/length as `addresses`: the 0-based line index into `source`
  // that statement's text starts at. Authoritative -- a top-level statement
  // doesn't always emit exactly one numbered line (IF/END IF and SUB/END
  // SUB blocks span several; grouped statements like "10 A=1:B=2" share
  // one), so this must not be re-derived by counting numbered lines.
  line_starts: number[]
}

export type ToggleInfo = { letter: string; name: string }

export type Instruction = { address: number; text: string; target: number | null }

export type RecompileResult = {
  matched: boolean
  ratio: number
  first_diff_offset: number | null
  original_len: number
  recompiled_len: number
  original_b64: string
  recompiled_b64: string
}

async function unwrap<T>(response: Response): Promise<T> {
  const body = await response.json()
  if (!response.ok) {
    throw new Error((body as ApiError).error ?? 'request failed')
  }
  return body as T
}

export async function decompile(file: File): Promise<DecompileResult> {
  const form = new FormData()
  form.append('exe', file)
  const response = await fetch('/api/decompile', { method: 'POST', body: form })
  return unwrap<DecompileResult>(response)
}

export async function recompile(
  sessionId: string,
  source: string,
  dialect?: string,
  toggles?: string
): Promise<RecompileResult> {
  const response = await fetch('/api/recompile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, source, dialect, toggles }),
  })
  return unwrap<RecompileResult>(response)
}

export async function listDialects(): Promise<string[]> {
  const response = await fetch('/api/dialects')
  const body = await unwrap<{ dialects: string[] }>(response)
  return body.dialects
}

export async function listToggles(): Promise<ToggleInfo[]> {
  const response = await fetch('/api/toggles')
  const body = await unwrap<{ toggles: ToggleInfo[] }>(response)
  return body.toggles
}

export async function disassemble(sessionId: string): Promise<Instruction[]> {
  const response = await fetch('/api/disassembly', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  })
  const body = await unwrap<{ instructions: Instruction[] }>(response)
  return body.instructions
}

// Stateless counterpart to disassemble(): the recompiled binary only ever
// exists as bytes already sent to the client (recompile() doesn't persist
// it server-side), so disassembling it takes those bytes directly.
export async function disassembleBytes(dataB64: string): Promise<Instruction[]> {
  const response = await fetch('/api/disassemble_bytes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data_b64: dataB64 }),
  })
  const body = await unwrap<{ instructions: Instruction[] }>(response)
  return body.instructions
}
