import { memo } from 'react'
import { format } from 'date-fns'
import { X } from 'lucide-react'
import type { AlertEvent } from '@/types'
import { Badge } from '@/components/ui/Badge'
import { SEVERITY_COLORS } from '@/lib/constants'

interface AlertItemProps {
  alert: AlertEvent
  onAcknowledge: (id: string) => void
}

function AlertItemInner({ alert, onAcknowledge }: AlertItemProps) {
  const time = format(new Date(alert.timestamp), 'HH:mm:ss')
  const color = SEVERITY_COLORS[alert.severity]

  return (
    <li
      className={`flex items-start gap-2 rounded-md border border-border bg-surface-raised p-2 text-sm animate-[slide-in_150ms_ease-out] ${
        alert.acknowledged ? 'opacity-50' : ''
      }`}
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <div className="flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-content-secondary">{time}</span>
          <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
          <span className="text-content-primary">{alert.category}</span>
        </div>
        <div className="text-xs text-content-secondary">
          <span className="font-mono text-content-primary">{alert.sourceIp}</span>
          {' → '}
          <span className="font-mono text-content-primary">{alert.destinationIp}</span>
        </div>
        {alert.message && (
          <div className="text-xs text-content-secondary">{alert.message}</div>
        )}
      </div>
      <button
        type="button"
        onClick={() => onAcknowledge(alert.id)}
        aria-label="Acknowledge alert"
        className="rounded p-1 text-content-secondary hover:bg-surface-base hover:text-content-primary"
      >
        <X className="h-4 w-4" />
      </button>
    </li>
  )
}

export const AlertItem = memo(AlertItemInner)
