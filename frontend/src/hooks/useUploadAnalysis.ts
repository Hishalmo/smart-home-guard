import { useMutation } from '@tanstack/react-query'
import { analyzePcap } from '@/services/analysisService'
import { useScanStore } from '@/store/scanStore'
import { useUiStore } from '@/store/uiStore'

export function useUploadAnalysis() {
  const { setStatus, setSessionId, setUploadProgress } = useScanStore()
  const { pushToast } = useUiStore()

  return useMutation({
    mutationFn: (file: File) =>
      analyzePcap(file, (pct) => useScanStore.getState().setUploadProgress(pct)),

    onMutate: () => {
      setStatus('scanning')
      setUploadProgress(0)
      setSessionId(null)
    },

    onSuccess: (data) => {
      setSessionId(data.session_id)
      setUploadProgress(100)
      // Flows and alerts arrive via Supabase realtime (useRealtimeFlows).
      // Status flips to 'completed' from useSessionStatus when the backend finishes.
    },

    onError: (err) => {
      setStatus('error')
      pushToast({
        message: err instanceof Error ? err.message : 'Analysis failed',
        severity: 'critical',
      })
    },
  })
}
