import type { IrNode } from './api'

type Props = { nodes: IrNode[] }

export default function IrTab({ nodes }: Props) {
  return <div>IR ({nodes.length} top-level nodes)</div>
}
