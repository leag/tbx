import { describe, expect, it } from 'vitest'
import { toGraph } from './irGraphLayout'
import { IrNode } from './api'

describe('toGraph', () => {
  it('creates one graph node per IR node and edges to nested children', () => {
    const nodes: IrNode[] = [
      {
        type: 'Assign',
        fields: {},
        children: [
          { name: 'target', node: { type: 'Var', fields: { name: 'A' }, children: [] } },
        ],
      },
    ]

    const { nodes: rfNodes, edges: rfEdges } = toGraph(nodes)

    expect(rfNodes).toHaveLength(2)
    expect(rfNodes.map((n) => n.data.label)).toEqual(
      expect.arrayContaining([expect.stringContaining('Assign'), expect.stringContaining('Var')])
    )
    expect(rfEdges).toHaveLength(1)
    expect(rfEdges[0].source).toBe(rfNodes[0].id)
    expect(rfEdges[0].target).toBe(rfNodes[1].id)
  })

  it('creates an edge per element for a tuple-of-nodes child', () => {
    const nodes: IrNode[] = [
      {
        type: 'ArrayRef',
        fields: { name: 'A' },
        children: [
          {
            name: 'indices',
            nodes: [
              { type: 'Lit', fields: { value: 0 }, children: [] },
              { type: 'Lit', fields: { value: 1 }, children: [] },
            ],
          },
        ],
      },
    ]

    const { nodes: rfNodes, edges: rfEdges } = toGraph(nodes)

    expect(rfNodes).toHaveLength(3)
    expect(rfEdges).toHaveLength(2)
  })
})
