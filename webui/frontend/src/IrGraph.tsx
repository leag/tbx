import ReactFlow, { Background, Controls } from 'reactflow'
import 'reactflow/dist/style.css'
import { IrNode } from './api'
import { toGraph } from './irGraphLayout'

type Props = { nodes: IrNode[] }

export default function IrGraph({ nodes }: Props) {
  const { nodes: rfNodes, edges: rfEdges } = toGraph(nodes)

  return (
    <div style={{ height: 600 }}>
      <ReactFlow nodes={rfNodes} edges={rfEdges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}
