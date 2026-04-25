import { create } from 'zustand'
import type { ScanMode, ScanStatus, NetworkFlow, FlowSummary } from '@/types'

const MAX_LIVE_FLOWS = 50
const TOP_IPS_LIMIT = 10

const EMPTY_SUMMARY: FlowSummary = {
  totalFlows: 0,
  benignCount: 0,
  bruteForceCount: 0,
  reconCount: 0,
  spoofingCount: 0,
  benignPercent: 0,
  activeThreats: 0,
  protocolCounts: {},
  topSourceIps: [],
}

interface ScanState {
  sessionId: string | null
  mode: ScanMode
  status: ScanStatus
  selectedInterface: string | null
  uploadProgress: number
  liveFlows: NetworkFlow[]
  flowSummary: FlowSummary | null
  ipCounts: Record<string, number>
  setMode: (mode: ScanMode) => void
  setInterface: (iface: string | null) => void
  setStatus: (status: ScanStatus) => void
  setSessionId: (id: string | null) => void
  setUploadProgress: (progress: number) => void
  pushFlow: (flow: NetworkFlow) => void
  setFlowSummary: (summary: FlowSummary) => void
  resetScan: () => void
}

const initialState = {
  sessionId: null,
  mode: 'pcap' as ScanMode,
  status: 'idle' as ScanStatus,
  selectedInterface: null,
  uploadProgress: 0,
  liveFlows: [] as NetworkFlow[],
  flowSummary: null,
  ipCounts: {} as Record<string, number>,
}

export const useScanStore = create<ScanState>()((set) => ({
  ...initialState,
  setMode: (mode) => set({ mode }),
  setInterface: (iface) => set({ selectedInterface: iface }),
  setStatus: (status) => set({ status }),
  setSessionId: (id) => set({ sessionId: id }),
  setUploadProgress: (progress) => set({ uploadProgress: progress }),
  pushFlow: (flow) =>
    set((state) => {
      const liveFlows = [flow, ...state.liveFlows].slice(0, MAX_LIVE_FLOWS)

      const current = state.flowSummary ?? EMPTY_SUMMARY
      const category = flow.prediction.category
      const totalFlows = current.totalFlows + 1
      const benignCount = current.benignCount + (category === 'Benign' ? 1 : 0)
      const bruteForceCount = current.bruteForceCount + (category === 'BruteForce' ? 1 : 0)
      const reconCount = current.reconCount + (category === 'Recon' ? 1 : 0)
      const spoofingCount = current.spoofingCount + (category === 'Spoofing' ? 1 : 0)

      const proto = flow.protocolName
      const protocolCounts = proto
        ? { ...current.protocolCounts, [proto]: (current.protocolCounts[proto] ?? 0) + 1 }
        : current.protocolCounts

      const src = flow.sourceIp
      const ipCounts =
        src && src !== 'UNKNOWN'
          ? { ...state.ipCounts, [src]: (state.ipCounts[src] ?? 0) + 1 }
          : state.ipCounts

      const topSourceIps = Object.entries(ipCounts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, TOP_IPS_LIMIT)

      const flowSummary: FlowSummary = {
        totalFlows,
        benignCount,
        bruteForceCount,
        reconCount,
        spoofingCount,
        benignPercent: totalFlows > 0 ? (benignCount / totalFlows) * 100 : 0,
        activeThreats: totalFlows - benignCount,
        protocolCounts,
        topSourceIps,
      }

      return { liveFlows, flowSummary, ipCounts }
    }),
  setFlowSummary: (summary) => set({ flowSummary: summary }),
  resetScan: () => set(initialState),
}))
