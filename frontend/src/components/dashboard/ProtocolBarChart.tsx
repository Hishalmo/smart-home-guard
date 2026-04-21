import { useEffect, useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  LabelList,
  Cell,
  ResponsiveContainer,
} from 'recharts'
import { PROTOCOLS, IOT_PROTOCOLS } from '@/lib/constants'
import { Skeleton } from '@/components/ui/Skeleton'

interface ProtocolBarChartProps {
  protocolCounts: Record<string, number>
  loading?: boolean
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

export function ProtocolBarChart({ protocolCounts, loading }: ProtocolBarChartProps) {
  const axisColor = useAxisColor()

  if (loading) {
    return <Skeleton className="h-80 w-full" />
  }

  const data = PROTOCOLS.map((proto) => {
    const key = Object.keys(protocolCounts).find(
      (k) => k.toLowerCase() === proto.toLowerCase(),
    )
    return {
      protocol: proto,
      count: key ? protocolCounts[key] : 0,
      isIot: IOT_PROTOCOLS.includes(proto),
    }
  })

  const maxCount = Math.max(...data.map((d) => d.count), 1)

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 10, right: 40, left: 10, bottom: 10 }}
        >
          <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" horizontal={false} />
          <XAxis
            type="number"
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 12 }}
            allowDecimals={false}
            domain={[0, maxCount]}
          />
          <YAxis
            type="category"
            dataKey="protocol"
            stroke={axisColor}
            tick={{ fill: axisColor, fontSize: 12 }}
            width={60}
          />
          <Tooltip
            contentStyle={{
              background: 'hsl(var(--surface-raised))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              color: 'hsl(var(--content-primary))',
            }}
            cursor={{ fill: 'hsl(var(--border) / 0.3)' }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((entry) => (
              <Cell
                key={entry.protocol}
                fill={
                  entry.isIot
                    ? 'hsl(var(--accent))'
                    : 'hsl(var(--content-secondary) / 0.5)'
                }
              />
            ))}
            <LabelList
              dataKey="count"
              position="right"
              style={{ fill: axisColor, fontSize: 12 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
