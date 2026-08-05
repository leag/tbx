import { useState } from 'react'
import { IrNode } from './api'
import IrTree from './IrTree'
import IrGraph from './IrGraph'

type Props = { nodes: IrNode[] }

export default function IrTab({ nodes }: Props) {
  const [view, setView] = useState<'tree' | 'graph'>('tree')

  return (
    <div>
      <div role="tablist">
        <button role="tab" aria-selected={view === 'tree'} onClick={() => setView('tree')}>
          Tree
        </button>
        <button role="tab" aria-selected={view === 'graph'} onClick={() => setView('graph')}>
          Graph
        </button>
      </div>
      {view === 'tree' ? <IrTree nodes={nodes} /> : <IrGraph nodes={nodes} />}
    </div>
  )
}
