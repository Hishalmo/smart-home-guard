import type { LucideIcon } from 'lucide-react'
import { Skeleton } from '@/components/ui/Skeleton'

interface KpiCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: LucideIcon
  accentColor: string
  loading?: boolean
}

export function KpiCard({
  title,
  value,
  subtitle,
  icon: Icon,
  accentColor,
  loading,
}: KpiCardProps) {
  return (
    <div
      className="flex flex-col gap-2 rounded-md border border-border bg-surface-raised p-4 pl-5"
      style={{ borderLeft: `4px solid ${accentColor}` }}
    >
      <Icon className="h-5 w-5" style={{ color: accentColor }} aria-hidden />
      {loading ? (
        <Skeleton className="h-8 w-24" />
      ) : (
        <span className="text-[2rem] font-bold leading-tight text-content-primary">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
      )}
      <span className="text-sm font-medium text-content-primary">{title}</span>
      {subtitle && (
        <span className="text-xs text-content-secondary">{subtitle}</span>
      )}
    </div>
  )
}
