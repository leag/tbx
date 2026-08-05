import { describe, expect, it, vi, afterEach } from 'vitest'
import { decompile, recompile } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('decompile', () => {
  it('returns the parsed body on success', async () => {
    const body = { session_id: 's1', dialect: '1.1', source: '10 END', ir: [] }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(body),
    }))

    const result = await decompile(new File([new Uint8Array([1, 2])], 'x.exe'))

    expect(result).toEqual(body)
  })

  it('throws the server error text on failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      json: () => Promise.resolve({ error: 'boom [phase=lift]' }),
    }))

    await expect(decompile(new File([], 'x.exe'))).rejects.toThrow('boom [phase=lift]')
  })
})

describe('recompile', () => {
  it('returns the parsed body on success', async () => {
    const body = { matched: true, ratio: 1.0, first_diff_offset: null, original_len: 10, recompiled_len: 10 }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(body),
    }))

    const result = await recompile('s1', '10 END')

    expect(result).toEqual(body)
  })
})
