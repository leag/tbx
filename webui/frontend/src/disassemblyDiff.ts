import type { Instruction } from './api'

export type DiffRow =
  | { kind: 'same'; original: Instruction; recompiled: Instruction }
  | { kind: 'removed'; original: Instruction }
  | { kind: 'added'; recompiled: Instruction }

// Above this, the O(n*m) LCS table gets too big to build on every
// recompile click -- diffing stops being useful for human review long
// before it stops being computable, so there's no real loss in refusing.
const MAX_DIFFABLE_INSTRUCTIONS = 4000

// Aligns two instruction streams by their text (not address: the real
// compiler's addressing has no reason to match tbx's, so diffing on
// address would flag every line as different even when the code is
// identical). Classic LCS backtrace, same idea as a textual line diff.
export function diffInstructions(original: Instruction[], recompiled: Instruction[]): DiffRow[] | null {
  const n = original.length
  const m = recompiled.length
  if (n * m > MAX_DIFFABLE_INSTRUCTIONS * MAX_DIFFABLE_INSTRUCTIONS) return null

  // dp[i][j] = length of the LCS of original[i:] and recompiled[j:]
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        original[i].text === recompiled[j].text
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }

  const rows: DiffRow[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (original[i].text === recompiled[j].text) {
      rows.push({ kind: 'same', original: original[i], recompiled: recompiled[j] })
      i++
      j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ kind: 'removed', original: original[i] })
      i++
    } else {
      rows.push({ kind: 'added', recompiled: recompiled[j] })
      j++
    }
  }
  while (i < n) rows.push({ kind: 'removed', original: original[i++] })
  while (j < m) rows.push({ kind: 'added', recompiled: recompiled[j++] })
  return rows
}
