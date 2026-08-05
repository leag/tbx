import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import IrTree from './IrTree'
import { IrNode } from './api'

describe('IrTree', () => {
  it('renders a node type and its nested child', () => {
    const nodes: IrNode[] = [
      {
        type: 'Assign',
        fields: {},
        children: [
          { name: 'target', node: { type: 'Var', fields: { name: 'A' }, children: [] } },
          { name: 'value', node: { type: 'Lit', fields: { value: 1 }, children: [] } },
        ],
      },
    ]

    render(<IrTree nodes={nodes} />)

    expect(screen.getByText(/Assign/)).toBeInTheDocument()
    expect(screen.getByText(/Var/)).toBeInTheDocument()
    expect(screen.getByText(/Lit/)).toBeInTheDocument()
  })
})
