interface TopSourceIpsProps {
  topIps: Array<{ ip: string; count: number }>
}

export function TopSourceIps({ topIps }: TopSourceIpsProps) {
  if (!topIps || topIps.length === 0) {
    return (
      <div className="flex h-40 w-full items-center justify-center rounded-md border border-border bg-surface-raised text-content-secondary">
        No traffic yet
      </div>
    )
  }

  const rows = topIps.slice(0, 10)
  const maxCount = Math.max(...rows.map((r) => r.count), 1)

  return (
    <ul className="w-full space-y-2">
      {rows.map((row, i) => {
        const pct = (row.count / maxCount) * 100
        const isTop = i === 0
        return (
          <li key={row.ip} className="flex items-center gap-3 text-sm">
            <span className="w-32 truncate font-mono text-content-primary">
              {row.ip}
            </span>
            <div className="relative h-3 flex-1 rounded-sm bg-border/40">
              <div
                className={`absolute inset-y-0 left-0 rounded-sm ${
                  isTop ? 'bg-threat-spoofing' : 'bg-accent'
                }`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="w-16 text-right tabular-nums text-content-secondary">
              {row.count.toLocaleString()}
            </span>
          </li>
        )
      })}
    </ul>
  )
}
