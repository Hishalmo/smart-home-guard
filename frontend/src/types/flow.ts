import type { PredictionResult } from './ml'

export interface NetworkFlow {
  id: string
  sessionId: string
  timestamp: string
  sourceIp: string
  destinationIp: string
  sourcePort: number
  destinationPort: number
  protocolType: number
  protocolName: string
  flowDuration: number
  headerLength: number
  rate: number
  finFlagNumber: number
  synFlagNumber: number
  rstFlagNumber: number
  pshFlagNumber: number
  ackFlagNumber: number
  urgFlagNumber?: number
  eceFlagNumber: number
  cwrFlagNumber: number
  ackCount: number
  synCount: number
  finCount: number
  urgCount: number
  rstCount: number
  maxLength: number
  minLength: number
  sumLength: number
  avgLength: number
  stdLength: number
  mqtt?: 0 | 1
  coap?: 0 | 1
  http: 0 | 1
  https: 0 | 1
  dns: 0 | 1
  ssh: 0 | 1
  tcp: 0 | 1
  udp: 0 | 1
  arp: 0 | 1
  icmp: 0 | 1
  igmp?: 0 | 1
  totSum: number
  totSize: number
  iat: number
  magnitude: number
  covariance: number
  variance: number
  flowIdleTime?: number
  flowActiveTime?: number
  prediction: PredictionResult
}

export interface FlowSummary {
  totalFlows: number
  benignCount: number
  bruteForceCount: number
  reconCount: number
  spoofingCount: number
  benignPercent: number
  activeThreats: number
  protocolCounts: Record<string, number>
  topSourceIps: Array<{ ip: string; count: number }>
}
