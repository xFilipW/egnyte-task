import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * Lightweight progress/meter. Kept dependency-free (no Radix) so the strength
 * meter can be tinted per-segment via `indicatorClassName`.
 */
function Progress({ className, value = 0, indicatorClassName, ...props }) {
  return (
    <div
      data-slot="progress"
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      className={cn(
        'bg-primary/15 relative h-2.5 w-full overflow-hidden rounded-full',
        className,
      )}
      {...props}
    >
      <div
        data-slot="progress-indicator"
        className={cn(
          'h-full w-full flex-1 rounded-full transition-all duration-500 ease-out',
          indicatorClassName ?? 'bg-primary',
        )}
        style={{ transform: `translateX(-${100 - Math.min(100, Math.max(0, value))}%)` }}
      />
    </div>
  )
}

export { Progress }
