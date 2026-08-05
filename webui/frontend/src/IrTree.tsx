import type { IrNode } from './api'
import { colorForType } from './irColors'

function fieldsSummary(fields: Record<string, unknown>): string {
  const entries = Object.entries(fields)
  if (entries.length === 0) return ''
  return ' ' + entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ')
}

function TreeNode({ node, depth }: { node: IrNode; depth: number }) {
  return (
    <div style={{ marginLeft: depth * 16 }}>
      <span style={{ color: colorForType(node.type), fontWeight: 'bold' }}>{node.type}</span>
      <span>{fieldsSummary(node.fields)}</span>
      {node.children.map((child, i) => (
        <div key={i}>
          <div style={{ marginLeft: (depth + 1) * 16, opacity: 0.6 }}>{child.name}:</div>
          {'node' in child ? (
            <TreeNode node={child.node} depth={depth + 2} />
          ) : (
            child.nodes.map((n, j) => <TreeNode key={j} node={n} depth={depth + 2} />)
          )}
        </div>
      ))}
    </div>
  )
}

export default function IrTree({ nodes }: { nodes: IrNode[] }) {
  return (
    <div style={{ fontFamily: 'monospace' }}>
      {nodes.map((node, i) => (
        <TreeNode key={i} node={node} depth={0} />
      ))}
    </div>
  )
}
