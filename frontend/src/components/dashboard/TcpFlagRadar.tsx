import { useEffect, useState } from 'react'
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

interface FlagDatum {
  flag: string
  value: number
}

interface TcpFlagRadarProps {
  flagData: FlagDatum[]
}

const FLAG_ORDER = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'] as const

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

export function TcpFlagRadar({ flagData }: TcpFlagRadarProps) {
  const axisColor = useAxisColor()

  if (!flagData || flagData.length === 0) {
    return (
      <div className="flex h-80 w-full items-center justify-center rounded-md border border-border bg-surface-raised text-content-secondary">
        No flag data
      </div>
    )
  }

  const byFlag = new Map(flagData.map((d) => [d.flag.toUpperCase(), d.value]))
  const data = FLAG_ORDER.map((flag) => ({
    flag,
    value: byFlag.get(flag) ?? 0,
  }))

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <RadarChart data={data} outerRadius="75%">
          <PolarGrid stroke="hsl(var(--border))" />
          <PolarAngleAxis
            dataKey="flag"
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 12 }}
          />
          <PolarRadiusAxis
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 10 }}
            angle={90}
          />
          <Tooltip
            contentStyle={{
              background: 'hsl(var(--surface-raised))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              color: 'hsl(var(--content-primary))',
            }}
          />
          <Radar
            name="TCP flags"
            dataKey="value"
            stroke="hsl(var(--accent))"
            fill="hsl(var(--accent))"
            fillOpacity={0.4}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  )
}
