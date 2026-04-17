import { clsx } from 'clsx'

const variants = {
  scanning: { dot: 'bg-threat-benign', label: 'Scanning', animate: true },
  idle: { dot: 'bg-content-secondary', label: 'Idle', animate: false },
  error: { dot: 'bg-severity-critical', label: 'Error', animate: false },
  starting: { dot: 'bg-severity-medium', label: 'Starting', animate: true },
} as const

interface StatusPillProps {
  status: keyof typeof variants
}

export function StatusPill({ status }: StatusPillProps) {
  const { dot, label, animate } = variants[status]
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-border bg-surface-raised px-3 py-1 text-xs font-medium text-content-primary">
      <span
        className={clsx('h-2 w-2 rounded-full', dot, animate && 'animate-pulse')}
      />
      {label}
    </span>
  )
}
