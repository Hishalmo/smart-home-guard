import type { NetworkFlow } from '@/types'
import { useUiStore } from '@/store/uiStore'
import { Skeleton } from '@/components/ui/Skeleton'
import { FlowTableRow } from './FlowTableRow'

interface FlowTableProps {
  flows: NetworkFlow[]
  loading?: boolean
}

export function FlowTable({ flows, loading }: FlowTableProps) {
  const selectedFlowId = useUiStore((s) => s.selectedFlowId)
  const selectFlow = useUiStore((s) => s.selectFlow)

  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  if (!flows || flows.length === 0) {
    return (
      <div className="flex h-40 w-full items-center justify-center rounded-md border border-border bg-surface-raised text-content-secondary">
        No flows yet — start a scan or upload a PCAP
      </div>
    )
  }

  return (
    <div className="max-h-[400px] overflow-auto rounded-md border border-border">
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-surface-raised">
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-content-secondary">
            <th className="w-8 px-3 py-2" />
            <th className="px-3 py-2 font-medium">Time</th>
            <th className="px-3 py-2 font-medium">Src IP</th>
            <th className="px-3 py-2 font-medium">Dst IP</th>
            <th className="px-3 py-2 font-medium">Protocol</th>
            <th className="px-3 py-2 text-right font-medium">Duration</th>
            <th className="px-3 py-2 text-right font-medium">Rate</th>
            <th className="px-3 py-2 font-medium">Class</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((flow) => (
            <FlowTableRow
              key={flow.id}
              flow={flow}
              isExpanded={selectedFlowId === flow.id}
              onToggle={() =>
                selectFlow(selectedFlowId === flow.id ? null : flow.id)
              }
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}
