import { useEffect, useState } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { format } from 'date-fns'
import { CLASS_COLORS } from '@/lib/constants'

interface TimelinePoint {
  timestamp: string
  benign: number
  spoofing: number
  recon: number
  bruteForce: number
}

interface ThreatTimelineProps {
  timelineData: TimelinePoint[]
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

export function ThreatTimeline({ timelineData }: ThreatTimelineProps) {
  const axisColor = useAxisColor()

  if (!timelineData || timelineData.length === 0) {
    return (
      <div className="flex h-72 w-full items-center justify-center rounded-md border border-border bg-surface-raised text-content-secondary">
        No timeline data
      </div>
    )
  }

  const data = timelineData.slice(-30).map((p) => ({
    ...p,
    label: format(new Date(p.timestamp), 'HH:mm:ss'),
  }))

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" />
          <XAxis
            dataKey="label"
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 12 }}
          />
          <YAxis
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 12 }}
            allowDecimals={false}
            label={{
              value: 'Events',
              angle: -90,
              position: 'insideLeft',
              fill: axisColor,
              fontSize: 12,
            }}
          />
          <Tooltip
            contentStyle={{
              background: 'hsl(var(--surface-raised))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              color: 'hsl(var(--content-primary))',
            }}
            labelStyle={{ color: 'hsl(var(--content-primary))' }}
          />
          <Legend wrapperStyle={{ color: axisColor, fontSize: 12 }} />
          <Line
            type="monotone"
            dataKey="spoofing"
            name="Spoofing"
            stroke={CLASS_COLORS.Spoofing}
            strokeWidth={2}
            dot={false}
            fill="none"
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="recon"
            name="Recon"
            stroke={CLASS_COLORS.Recon}
            strokeWidth={2}
            dot={false}
            fill="none"
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="bruteForce"
            name="BruteForce"
            stroke={CLASS_COLORS.BruteForce}
            strokeWidth={2}
            dot={false}
            fill="none"
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
