import { Activity, ShieldAlert, ShieldCheck, Brain } from 'lucide-react'
import type { FlowSummary } from '@/types'
import { CLASS_COLORS, MODEL_INFO, SEVERITY_COLORS } from '@/lib/constants'
import { KpiCard } from './KpiCard'

interface KpiGridProps {
  summary: FlowSummary | null
  loading?: boolean
}

export function KpiGrid({ summary, loading }: KpiGridProps) {
  const isLoading = loading || !summary

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <KpiCard
        title="Total Flows"
        value={summary?.totalFlows ?? 0}
        icon={Activity}
        accentColor="hsl(var(--accent))"
        loading={isLoading}
      />
      <KpiCard
        title="Active Threats"
        value={summary?.activeThreats ?? 0}
        icon={ShieldAlert}
        accentColor={SEVERITY_COLORS.critical}
        loading={isLoading}
      />
      <KpiCard
        title="Benign %"
        value={summary ? `${summary.benignPercent.toFixed(1)}%` : '—'}
        icon={ShieldCheck}
        accentColor={CLASS_COLORS.Benign}
        loading={isLoading}
      />
      <KpiCard
        title="Model Accuracy"
        value={MODEL_INFO.accuracy}
        subtitle={`${MODEL_INFO.name} · ${MODEL_INFO.classes} classes`}
        icon={Brain}
        accentColor="hsl(var(--accent))"
      />
    </div>
  )
}
