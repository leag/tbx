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
  source: string
  ir: IrNode[]
}

export type RecompileResult = {
  matched: boolean
  ratio: number
  first_diff_offset: number | null
  original_len: number
  recompiled_len: number
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

export async function recompile(sessionId: string, source: string): Promise<RecompileResult> {
  const response = await fetch('/api/recompile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, source }),
  })
  return unwrap<RecompileResult>(response)
}
