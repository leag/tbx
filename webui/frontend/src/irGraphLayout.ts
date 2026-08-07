import dagre from 'dagre'
import type { Node as RFNode, Edge as RFEdge } from 'reactflow'
import type { IrNode } from './api'
import { colorForType, fieldsSummary } from './irColors'

const NODE_WIDTH = 180
const NODE_HEIGHT = 40

export function toGraph(roots: IrNode[]): { nodes: RFNode[]; edges: RFEdge[] } {
  const nodes: RFNode[] = []
  const edges: RFEdge[] = []
  let counter = 0

  function visit(irNode: IrNode): string {
    const id = `n${counter++}`
    nodes.push({
      id,
      data: { label: irNode.type + fieldsSummary(irNode.fields, { prefix: '\n', sep: ', ' }) },
      position: { x: 0, y: 0 },
      style: { borderColor: colorForType(irNode.type), borderWidth: 2, width: NODE_WIDTH },
    })
    for (const child of irNode.children) {
      if ('node' in child) {
        const childId = visit(child.node)
        edges.push({ id: `${id}-${childId}`, source: id, target: childId, label: child.name })
      } else {
        for (const n of child.nodes) {
          const childId = visit(n)
          edges.push({ id: `${id}-${childId}`, source: id, target: childId, label: child.name })
        }
      }
    }
    return id
  }

  for (const root of roots) visit(root)

  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'TB' })
  for (const n of nodes) g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  for (const e of edges) g.setEdge(e.source, e.target)
  dagre.layout(g)
  for (const n of nodes) {
    const pos = g.node(n.id)
    n.position = { x: pos.x, y: pos.y }
  }

  return { nodes, edges }
}
