import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from './App'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('App', () => {
  it('uploads a file and shows the decompiled source', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        session_id: 's1', dialect: '1.1', source: '10 PRINT "HI"', ir: [],
      }),
    }))

    render(<App />)
    const input = screen.getByLabelText(/upload/i) as HTMLInputElement
    const file = new File([new Uint8Array([1, 2, 3])], 'prog.exe')
    fireEvent.change(input, { target: { files: [file] } })

    await waitFor(() => {
      // The source editor (Task 9) uses CodeMirror, which renders each
      // token as its own span rather than one text node -- assert on the
      // container's aggregate textContent instead of a single getByText
      // match, which would miss text split across sibling spans.
      const editor = screen.getByLabelText(/source editor/i)
      expect(editor.textContent).toContain('10 PRINT "HI"')
    })
    expect(screen.getByRole('tab', { name: /source/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /ir/i })).toBeInTheDocument()
  })
})
