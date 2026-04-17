import { type ReactNode } from 'react'
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

const variantStyles = {
  benign: 'bg-threat-benign/15 text-threat-benign',
  brute: 'bg-threat-brute/15 text-threat-brute',
  recon: 'bg-threat-recon/15 text-threat-recon',
  spoofing: 'bg-threat-spoofing/15 text-threat-spoofing',
  critical: 'bg-severity-critical/15 text-severity-critical',
  high: 'bg-severity-high/15 text-severity-high',
  medium: 'bg-severity-medium/15 text-severity-medium',
  info: 'bg-severity-info/15 text-severity-info',
  default: 'bg-surface-base text-content-secondary',
} as const

interface BadgeProps {
  variant?: keyof typeof variantStyles
  children: ReactNode
  className?: string
}

export function Badge({ variant = 'default', children, className }: BadgeProps) {
  return (
    <span
      className={twMerge(
        clsx(
          'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
          variantStyles[variant],
        ),
        className,
      )}
    >
      {children}
    </span>
  )
}
