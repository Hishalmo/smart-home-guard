import { type ReactNode } from 'react'
import { twMerge } from 'tailwind-merge'

interface CardProps {
  title?: string
  description?: string
  children: ReactNode
  className?: string
}

export function Card({ title, description, children, className }: CardProps) {
  return (
    <div
      className={twMerge(
        'rounded-xl border border-border bg-surface-raised p-6',
        className,
      )}
    >
      {(title || description) && (
        <div className="mb-4">
          {title && (
            <h3 className="text-lg font-semibold text-content-primary">{title}</h3>
          )}
          {description && (
            <p className="mt-1 text-sm text-content-secondary">{description}</p>
          )}
        </div>
      )}
      {children}
    </div>
  )
}
