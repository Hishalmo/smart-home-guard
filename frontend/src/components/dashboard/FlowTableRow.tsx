import { memo } from 'react'
import { format } from 'date-fns'
import { ChevronRight } from 'lucide-react'
import type { NetworkFlow, ClassLabel } from '@/types'
import { Badge } from '@/components/ui/Badge'

interface FlowTableRowProps {
  flow: NetworkFlow
  isExpanded: boolean
  onToggle: () => void
}

const CATEGORY_VARIANT: Record<ClassLabel, 'benign' | 'brute' | 'recon' | 'spoofing'> = {
  Benign: 'benign',
  BruteForce: 'brute',
  Recon: 'recon',
  Spoofing: 'spoofing',
}

const COLSPAN = 8

function DetailGroup({
  title,
  entries,
}: {
  title: string
  entries: Array<[string, string | number]>
}) {
  return (
    <div className="rounded-md border border-border bg-surface-base p-3">
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-content-secondary">
        {title}
      </h4>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <dt className="text-content-secondary">{k}</dt>
            <dd className="font-mono text-content-primary">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

function FlowTableRowInner({ flow, isExpanded, onToggle }: FlowTableRowProps) {
  const time = format(new Date(flow.timestamp), 'HH:mm:ss')
  const variant = CATEGORY_VARIANT[flow.prediction.category]

  const connectivity: Array<[string, string | number]> = [
    ['src_port', flow.sourcePort],
    ['dst_port', flow.destinationPort],
    ['protocol_type', flow.protocolType],
    ['header_length', flow.headerLength],
    ['flow_duration', flow.flowDuration.toFixed(3)],
    ['rate', flow.rate.toFixed(2)],
  ]

  const tcpFlags: Array<[string, string | number]> = [
    ['FIN', flow.finFlagNumber],
    ['SYN', flow.synFlagNumber],
    ['RST', flow.rstFlagNumber],
    ['PSH', flow.pshFlagNumber],
    ['ACK', flow.ackFlagNumber],
    ['ECE', flow.eceFlagNumber],
    ['CWR', flow.cwrFlagNumber],
    ['ack_count', flow.ackCount],
    ['syn_count', flow.synCount],
    ['fin_count', flow.finCount],
    ['urg_count', flow.urgCount],
    ['rst_count', flow.rstCount],
  ]

  const protocolFlags: Array<[string, string | number]> = [
    ['http', flow.http],
    ['https', flow.https],
    ['dns', flow.dns],
    ['ssh', flow.ssh],
    ['tcp', flow.tcp],
    ['udp', flow.udp],
    ['arp', flow.arp],
    ['icmp', flow.icmp],
    ['igmp', flow.igmp],
  ]

  const stats: Array<[string, string | number]> = [
    ['max_length', flow.maxLength],
    ['min_length', flow.minLength],
    ['sum_length', flow.sumLength],
    ['avg_length', flow.avgLength.toFixed(2)],
    ['std_length', flow.stdLength.toFixed(2)],
    ['tot_sum', flow.totSum],
    ['tot_size', flow.totSize],
    ['iat', flow.iat.toFixed(3)],
    ['magnitude', flow.magnitude.toFixed(2)],
    ['covariance', flow.covariance.toFixed(2)],
    ['variance', flow.variance.toFixed(2)],
  ]

  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer border-b border-border hover:bg-surface-base"
      >
        <td className="px-3 py-2">
          <ChevronRight
            className={`h-4 w-4 text-content-secondary transition-transform ${isExpanded ? 'rotate-90' : ''
              }`}
          />
        </td>
        <td className="px-3 py-2 font-mono text-xs text-content-secondary">{time}</td>
        <td className="px-3 py-2 font-mono text-xs text-content-primary">{flow.sourceIp}</td>
        <td className="px-3 py-2 font-mono text-xs text-content-primary">
          {flow.destinationIp}
        </td>
        <td className="px-3 py-2 text-xs text-content-primary">{flow.protocolName}</td>
        <td className="px-3 py-2 text-right tabular-nums text-xs text-content-primary">
          {flow.flowDuration.toFixed(2)}s
        </td>
        <td className="px-3 py-2 text-right tabular-nums text-xs text-content-primary">
          {flow.rate.toFixed(1)}
        </td>
        <td className="px-3 py-2">
          <Badge variant={variant}>{flow.prediction.category}</Badge>
        </td>
      </tr>
      {isExpanded && (
        <tr className="border-b border-border bg-surface-base/50">
          <td colSpan={COLSPAN} className="px-3 py-3">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
              <DetailGroup title="Connectivity" entries={connectivity} />
              <DetailGroup title="TCP Flags" entries={tcpFlags} />
              <DetailGroup title="Protocol Flags" entries={protocolFlags} />
              <DetailGroup title="Statistical Features" entries={stats} />
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export const FlowTableRow = memo(FlowTableRowInner)
