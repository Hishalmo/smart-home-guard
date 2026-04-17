import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { clsx } from 'clsx'
import { useUiStore } from '@/store/uiStore'

const severityStyles = {
  critical: 'border-severity-critical/30 bg-severity-critical/10 text-severity-critical',
  high: 'border-severity-high/30 bg-severity-high/10 text-severity-high',
  medium: 'border-severity-medium/30 bg-severity-medium/10 text-severity-medium',
  info: 'border-severity-info/30 bg-severity-info/10 text-severity-info',
} as const

function ToastItem({ id, message, severity }: { id: string; message: string; severity: string }) {
  const dismissToast = useUiStore((s) => s.dismissToast)

  useEffect(() => {
    const timer = setTimeout(() => dismissToast(id), 4000)
    return () => clearTimeout(timer)
  }, [id, dismissToast])

  return (
    <div
      className={clsx(
        'flex items-center gap-3 rounded-lg border px-4 py-3 text-sm shadow-lg',
        severityStyles[severity as keyof typeof severityStyles] ?? severityStyles.info,
      )}
    >
      <span className="flex-1">{message}</span>
      <button onClick={() => dismissToast(id)} className="shrink-0 opacity-70 hover:opacity-100">
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

export function ToastContainer() {
  const toasts = useUiStore((s) => s.toasts)

  if (toasts.length === 0) return null

  return createPortal(
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} message={t.message} severity={t.severity} />
      ))}
    </div>,
    document.body,
  )
}
