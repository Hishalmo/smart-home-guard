import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, FileCheck } from 'lucide-react'
import { clsx } from 'clsx'
import { formatBytes } from '@/utils/formatters'

interface DropZoneProps {
  file: File | null
  onFileSelect: (file: File) => void
}

const ACCEPT = {
  'application/vnd.tcpdump.pcap': ['.pcap'],
  'application/octet-stream': ['.pcap', '.pcapng'],
}

export function DropZone({ file, onFileSelect }: DropZoneProps) {
  const onDrop = useCallback(
    (accepted: File[]) => {
      if (accepted.length > 0) onFileSelect(accepted[0])
    },
    [onFileSelect],
  )

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: ACCEPT,
    maxFiles: 1,
  })

  return (
    <div
      {...getRootProps()}
      className={clsx(
        'flex cursor-pointer flex-col items-center gap-3 rounded-xl border-2 border-dashed p-8 transition-colors',
        isDragActive
          ? 'border-accent bg-accent/5'
          : 'border-border hover:border-accent/50',
      )}
    >
      <input {...getInputProps()} />
      {file ? (
        <>
          <FileCheck className="h-10 w-10 text-threat-benign" />
          <div className="text-center">
            <p className="font-medium text-content-primary">{file.name}</p>
            <p className="text-sm text-content-secondary">{formatBytes(file.size)}</p>
          </div>
        </>
      ) : (
        <>
          <Upload className="h-10 w-10 text-content-secondary" />
          <div className="text-center">
            <p className="font-medium text-content-primary">
              Drop a PCAP file here or click to browse
            </p>
            <p className="text-sm text-content-secondary">.pcap and .pcapng files only</p>
          </div>
        </>
      )}
    </div>
  )
}
