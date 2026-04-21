import { useAlertStore } from '@/store/alertStore'
import { Badge } from '@/components/ui/Badge'
import { AlertItem } from './AlertItem'

export function AlertFeed() {
  const alerts = useAlertStore((s) => s.alerts)
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const acknowledgeAlert = useAlertStore((s) => s.acknowledgeAlert)
  const clearAlerts = useAlertStore((s) => s.clearAlerts)

  return (
    <section className="flex h-full flex-col rounded-md border border-border bg-surface-raised">
      <header className="flex items-center justify-between border-b border-border px-4 py-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-content-primary">Alerts</h3>
          {unreadCount > 0 && <Badge variant="critical">{unreadCount} unread</Badge>}
        </div>
        <button
          type="button"
          onClick={clearAlerts}
          disabled={alerts.length === 0}
          className="text-xs text-content-secondary hover:text-content-primary disabled:opacity-40"
        >
          Clear All
        </button>
      </header>

      <div className="max-h-[360px] overflow-auto p-2">
        {alerts.length === 0 ? (
          <div className="flex h-24 items-center justify-center text-sm text-content-secondary">
            No alerts
          </div>
        ) : (
          <ul className="space-y-2">
            {alerts.map((alert) => (
              <AlertItem
                key={alert.id}
                alert={alert}
                onAcknowledge={acknowledgeAlert}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
