import { IrNode } from './api'

type Props = { nodes: IrNode[] }

export default function IrGraph({ nodes }: Props) {
  return <div>Graph ({nodes.length} top-level nodes)</div>
}
