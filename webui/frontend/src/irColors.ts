const PALETTE = [
  '#e06c75', '#61afef', '#98c379', '#e5c07b', '#c678dd',
  '#56b6c2', '#d19a66', '#528bff',
]

export function colorForType(type: string): string {
  let hash = 0
  for (let i = 0; i < type.length; i++) {
    hash = (hash * 31 + type.charCodeAt(i)) >>> 0
  }
  return PALETTE[hash % PALETTE.length]
}
