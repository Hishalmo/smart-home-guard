import { type ReactNode } from 'react'

interface TooltipProps {
  text: string
  children: ReactNode
}

export function Tooltip({ text, children }: TooltipProps) {
  return (
    <span className="group relative inline-flex">
      {children}
      <span
        className="pointer-events-none absolute bottom-full left-1/2 mb-2 -translate-x-1/2
          whitespace-nowrap rounded-md bg-content-primary px-2.5 py-1 text-xs text-surface-base
          opacity-0 transition-opacity group-hover:opacity-100"
      >
        {text}
      </span>
    </span>
  )
}
