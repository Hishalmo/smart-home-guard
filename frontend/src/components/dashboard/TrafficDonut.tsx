import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import type { FlowSummary, ClassLabel } from '@/types'
import { CLASS_COLORS } from '@/lib/constants'
import { Skeleton } from '@/components/ui/Skeleton'

interface TrafficDonutProps {
  summary: FlowSummary | null
  loading?: boolean
}

interface Segment {
  name: ClassLabel
  value: number
  color: string
}

function useAxisColor() {
  const [color, setColor] = useState<string>('')

  useEffect(() => {
    const read = () => {
      const hsl = getComputedStyle(document.documentElement)
        .getPropertyValue('--content-secondary')
        .trim()
      setColor(hsl ? `hsl(${hsl})` : '')
    }
    read()
    const observer = new MutationObserver(read)
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    })
    return () => observer.disconnect()
  }, [])

  return color
}

export function TrafficDonut({ summary, loading }: TrafficDonutProps) {
  const axisColor = useAxisColor()

  if (loading) {
    return <Skeleton className="h-80 w-full" />
  }

  if (!summary || summary.totalFlows === 0) {
    return (
      <div className="flex h-80 w-full items-center justify-center rounded-md border border-border bg-surface-raised text-content-secondary">
        No scan data
      </div>
    )
  }

  const data: Segment[] = [
    { name: 'Benign', value: summary.benignCount, color: CLASS_COLORS.Benign },
    { name: 'Spoofing', value: summary.spoofingCount, color: CLASS_COLORS.Spoofing },
    { name: 'Recon', value: summary.reconCount, color: CLASS_COLORS.Recon },
    { name: 'BruteForce', value: summary.bruteForceCount, color: CLASS_COLORS.BruteForce },
  ]

  const total = summary.totalFlows

  return (
    <div className="flex h-full w-full flex-col">
      <div className="relative h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="60%"
              outerRadius="85%"
              paddingAngle={2}
              stroke="none"
              isAnimationActive={false}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: 'hsl(var(--surface-raised))',
                border: '1px solid hsl(var(--border))',
                borderRadius: 6,
                color: 'hsl(var(--content-primary))',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold text-content-primary">
            {total.toLocaleString()}
          </span>
          <span className="text-xs" style={{ color: axisColor }}>
            total flows
          </span>
        </div>
      </div>

      <ul className="mt-4 grid grid-cols-2 gap-2 text-sm">
        {data.map((seg) => {
          const pct = total > 0 ? (seg.value / total) * 100 : 0
          return (
            <li key={seg.name} className="flex items-center gap-2">
              <span
                className="h-3 w-3 rounded-sm"
                style={{ background: seg.color }}
              />
              <span className="text-content-primary">{seg.name}</span>
              <span className="ml-auto text-content-secondary">
                {seg.value.toLocaleString()} ({pct.toFixed(1)}%)
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
