import { useEffect } from 'react'
import { api } from '@/services/api'
import { useScanStore } from '@/store/scanStore'
import { useUiStore } from '@/store/uiStore'
import type { FlowSummary } from '@/types'

interface SessionStatusResponse {
  session_id: string
  status: 'scanning' | 'completed' | 'error' | 'idle'
  total_flows: number
  threat_count: number
  started_at: string | null
  ended_at: string | null
  summary_json: {
    total_flows?: number
    benign_count?: number
    spoofing_count?: number
    recon_count?: number
    brute_force_count?: number
    protocol_counts?: Record<string, number>
    top_source_ips?: Array<{ ip: string; count: number }>
    error?: string
  } | null
}

const POLL_INTERVAL_MS = 3000

export function useSessionStatus() {
  const sessionId = useScanStore((s) => s.sessionId)
  const status = useScanStore((s) => s.status)
  const setStatus = useScanStore((s) => s.setStatus)
  const setFlowSummary = useScanStore((s) => s.setFlowSummary)
  const pushToast = useUiStore((s) => s.pushToast)

  useEffect(() => {
    if (!sessionId || status !== 'scanning') return

    let cancelled = false

    const poll = async () => {
      try {
        const res = await api.get<SessionStatusResponse>(
          `/api/sessions/${sessionId}/status`,
        )
        if (cancelled) return

        if (res.data.status === 'completed') {
          const s = res.data.summary_json
          if (s) {
            const totalFlows = s.total_flows ?? 0
            const benignCount = s.benign_count ?? 0
            const summary: FlowSummary = {
              totalFlows,
              benignCount,
              bruteForceCount: s.brute_force_count ?? 0,
              reconCount: s.recon_count ?? 0,
              spoofingCount: s.spoofing_count ?? 0,
              benignPercent: totalFlows > 0 ? (benignCount / totalFlows) * 100 : 0,
              activeThreats: totalFlows - benignCount,
              protocolCounts: s.protocol_counts ?? {},
              topSourceIps: s.top_source_ips ?? [],
            }
            setFlowSummary(summary)
          }
          setStatus('completed')
          pushToast({
            message: `Analysis complete — ${res.data.total_flows} flows classified`,
            severity: 'info',
          })
        } else if (res.data.status === 'error') {
          setStatus('error')
          pushToast({
            message: res.data.summary_json?.error ?? 'Analysis failed',
            severity: 'critical',
          })
        }
      } catch {
        // Transient errors (network blip, 502 from backend) — keep polling.
      }
    }

    const id = setInterval(poll, POLL_INTERVAL_MS)
    poll()

    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [sessionId, status, setStatus, setFlowSummary, pushToast])
}
