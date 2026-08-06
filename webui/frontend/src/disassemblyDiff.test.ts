import { describe, expect, it } from 'vitest'
import { diffInstructions } from './disassemblyDiff'
import type { Instruction } from './api'

function ins(address: number, text: string): Instruction {
  return { address, text, target: null }
}

describe('diffInstructions', () => {
  it('marks identical streams as all same', () => {
    const a = [ins(0, 'nop'), ins(1, 'ret')]
    const b = [ins(0x100, 'nop'), ins(0x101, 'ret')]

    const rows = diffInstructions(a, b)

    expect(rows).not.toBeNull()
    expect(rows!.every((r) => r.kind === 'same')).toBe(true)
  })

  it('flags an inserted instruction as added, not a cascade of mismatches', () => {
    const a = [ins(0, 'nop'), ins(1, 'ret')]
    const b = [ins(0, 'nop'), ins(1, 'mov al,1'), ins(2, 'ret')]

    const rows = diffInstructions(a, b)

    expect(rows!.map((r) => r.kind)).toEqual(['same', 'added', 'same'])
  })

  it('flags a removed instruction', () => {
    const a = [ins(0, 'nop'), ins(1, 'mov al,1'), ins(2, 'ret')]
    const b = [ins(0, 'nop'), ins(1, 'ret')]

    const rows = diffInstructions(a, b)

    expect(rows!.map((r) => r.kind)).toEqual(['same', 'removed', 'same'])
  })

  it('refuses to diff streams too large to compute cheaply', () => {
    const big = Array.from({ length: 5000 }, (_, i) => ins(i, `nop ${i}`))

    expect(diffInstructions(big, big)).toBeNull()
  })
})
