import { useState } from 'react'
import { DropZone } from '@/components/ui/DropZone'
import { Button } from '@/components/ui/Button'
import { useScanStore } from '@/store/scanStore'
import { useUploadAnalysis } from '@/hooks/useUploadAnalysis'

export function PcapPanel() {
  const [file, setFile] = useState<File | null>(null)
  const { uploadProgress, status, flowSummary, resetScan } = useScanStore()
  const { mutate, isPending } = useUploadAnalysis()

  const isScanning = isPending || status === 'scanning'

  function handleAnalyze() {
    if (file) mutate(file)
  }

  function handleRetry() {
    resetScan()
    if (file) mutate(file)
  }

  return (
    <div className="flex flex-col gap-4">
      <DropZone file={file} onFileSelect={setFile} />

      {isScanning && (
        <div className="h-2 w-full overflow-hidden rounded-full bg-border">
          <div
            className="h-full rounded-full bg-accent transition-all duration-200"
            style={{ width: `${uploadProgress}%` }}
          />
        </div>
      )}

      <Button
        variant="primary"
        disabled={!file || isScanning}
        loading={isPending}
        onClick={handleAnalyze}
      >
        Analyze
      </Button>

      {status === 'completed' && flowSummary && (
        <div className="flex gap-4 rounded-lg border border-border bg-surface-base px-4 py-3 text-sm">
          <span className="text-content-primary">
            <span className="font-semibold">{flowSummary.totalFlows}</span>{' '}
            <span className="text-content-secondary">flows</span>
          </span>
          <span className="text-content-primary">
            <span className="font-semibold text-severity-critical">{flowSummary.activeThreats}</span>{' '}
            <span className="text-content-secondary">threats</span>
          </span>
          <span className="text-content-primary">
            <span className="font-semibold text-threat-benign">
              {flowSummary.benignPercent.toFixed(1)}%
            </span>{' '}
            <span className="text-content-secondary">benign</span>
          </span>
        </div>
      )}

      {status === 'error' && (
        <div className="flex items-center justify-between rounded-lg border border-severity-critical/30 bg-severity-critical/5 px-4 py-3">
          <span className="text-sm text-severity-critical">Analysis failed. Please try again.</span>
          <Button variant="outline" onClick={handleRetry}>
            Retry
          </Button>
        </div>
      )}
    </div>
  )
}
