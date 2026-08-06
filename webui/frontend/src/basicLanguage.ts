import { StreamLanguage } from '@codemirror/language'

// Minimal Turbo Basic syntax highlighting: no CodeMirror language package
// exists for it, so this is a small hand-rolled StreamLanguage covering just
// enough to make recovered source legible (keywords, strings, comments,
// numbers, line numbers) -- not a full parser.
const KEYWORDS = new Set([
  'AND', 'AS', 'BEEP', 'CALL', 'CASE', 'CHAIN', 'CLOSE', 'CLS', 'COLOR',
  'COMMON', 'CONST', 'DATA', 'DECLARE', 'DEF', 'DIM', 'DO', 'DRAW', 'ELSE',
  'ELSEIF', 'END', 'ENVIRON', 'ERASE', 'ERROR', 'EXIT', 'FIELD', 'FN', 'FOR',
  'FUNCTION', 'GET', 'GOSUB', 'GOTO', 'IF', 'INPUT', 'KEY', 'KILL', 'LET',
  'LINE', 'LOCAL', 'LOCATE', 'LOOP', 'LPRINT', 'MID$', 'NEXT', 'NOT', 'ON',
  'OPEN', 'OR', 'OUT', 'PAINT', 'PALETTE', 'PLAY', 'POKE', 'PRESET', 'PRINT',
  'PSET', 'PUT', 'RANDOMIZE', 'READ', 'REDIM', 'REM', 'RESTORE', 'RESUME',
  'RETURN', 'RUN', 'SCREEN', 'SEEK', 'SELECT', 'SHARED', 'SHELL', 'SOUND',
  'STATIC', 'STEP', 'STOP', 'SUB', 'SWAP', 'SYSTEM', 'THEN', 'TIMER', 'TO',
  'TROFF', 'TRON', 'UNTIL', 'USING', 'VIEW', 'WAIT', 'WEND', 'WHILE', 'WIDTH',
  'WINDOW', 'WRITE', 'XOR',
])

export const basicLanguage = StreamLanguage.define({
  startState() {
    return { afterLineNumber: false }
  },
  token(stream, state) {
    if (stream.sol()) {
      state.afterLineNumber = false
      if (stream.match(/^\d+/)) {
        state.afterLineNumber = true
        return 'number'
      }
    }
    if (stream.eatSpace()) return null
    if (stream.match("'")) {
      stream.skipToEnd()
      return 'comment'
    }
    if (stream.match('"')) {
      while (!stream.eol()) {
        if (stream.next() === '"') break
      }
      return 'string'
    }
    if (stream.match(/^&H[0-9A-Fa-f]+/)) return 'number'
    if (stream.match(/^\d+\.?\d*([eE][+-]?\d+)?[!#%]?/)) return 'number'
    const wordMatch = stream.match(/^[A-Za-z_][A-Za-z0-9_]*[$%!#]?/)
    if (wordMatch) {
      const word = String(Array.isArray(wordMatch) ? wordMatch[0] : stream.current()).toUpperCase()
      if (word === 'REM') {
        stream.skipToEnd()
        return 'comment'
      }
      if (KEYWORDS.has(word)) return 'keyword'
      return 'variableName'
    }
    if (stream.match(/^[+\-*/^=<>]+/)) return 'operator'
    stream.next()
    return null
  },
})
