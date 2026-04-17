import { type ReactNode } from 'react'
import { twMerge } from 'tailwind-merge'

export interface Column<T> {
  header: string
  accessor: (row: T) => ReactNode
  sortKey?: string
}

interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyExtractor: (row: T) => string
  emptyState?: ReactNode
  className?: string
  onSort?: (key: string) => void
  sortKey?: string
  sortDir?: 'asc' | 'desc'
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  emptyState,
  className,
  onSort,
  sortKey,
  sortDir,
}: TableProps<T>) {
  if (data.length === 0 && emptyState) {
    return <div className="py-12 text-center text-content-secondary">{emptyState}</div>
  }

  return (
    <div className={twMerge('overflow-auto', className)}>
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 border-b border-border bg-surface-raised text-xs uppercase text-content-secondary">
          <tr>
            {columns.map((col) => (
              <th
                key={col.header}
                className="px-4 py-3 font-medium"
                onClick={col.sortKey && onSort ? () => onSort(col.sortKey!) : undefined}
                style={col.sortKey && onSort ? { cursor: 'pointer' } : undefined}
              >
                <span className="inline-flex items-center gap-1">
                  {col.header}
                  {col.sortKey && sortKey === col.sortKey && (
                    <span>{sortDir === 'asc' ? '↑' : '↓'}</span>
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr
              key={keyExtractor(row)}
              className="border-b border-border transition-colors hover:bg-surface-base"
            >
              {columns.map((col) => (
                <td key={col.header} className="px-4 py-3 text-content-primary">
                  {col.accessor(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
