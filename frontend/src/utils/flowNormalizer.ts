import type { NetworkFlow } from '@/types'

const DEFAULT_FLOW: NetworkFlow = {
  id: '',
  sessionId: '',
  timestamp: '',
  sourceIp: 'UNKNOWN',
  destinationIp: 'UNKNOWN',
  sourcePort: 0,
  destinationPort: 0,
  protocolType: 0,
  protocolName: 'UNKNOWN',
  flowDuration: 0,
  headerLength: 0,
  rate: 0,
  finFlagNumber: 0,
  synFlagNumber: 0,
  rstFlagNumber: 0,
  pshFlagNumber: 0,
  ackFlagNumber: 0,
  eceFlagNumber: 0,
  cwrFlagNumber: 0,
  ackCount: 0,
  synCount: 0,
  finCount: 0,
  urgCount: 0,
  rstCount: 0,
  maxLength: 0,
  minLength: 0,
  sumLength: 0,
  avgLength: 0,
  stdLength: 0,
  http: 0,
  https: 0,
  dns: 0,
  ssh: 0,
  tcp: 0,
  udp: 0,
  arp: 0,
  icmp: 0,
  totSum: 0,
  totSize: 0,
  iat: 0,
  magnitude: 0,
  covariance: 0,
  variance: 0,
  prediction: { category: 'Benign', confidence: 0 },
}

const FIELD_MAP: Record<string, string> = {
  id: 'id',
  session_id: 'sessionId',
  captured_at: 'timestamp',
  source_ip: 'sourceIp',
  destination_ip: 'destinationIp',
  source_port: 'sourcePort',
  destination_port: 'destinationPort',
  protocol_type: 'protocolType',
  protocol_name: 'protocolName',
  flow_duration: 'flowDuration',
  header_length: 'headerLength',
  rate: 'rate',
  fin_flag_number: 'finFlagNumber',
  syn_flag_number: 'synFlagNumber',
  rst_flag_number: 'rstFlagNumber',
  psh_flag_number: 'pshFlagNumber',
  ack_flag_number: 'ackFlagNumber',
  urg_flag_number: 'urgFlagNumber',
  ece_flag_number: 'eceFlagNumber',
  cwr_flag_number: 'cwrFlagNumber',
  ack_count: 'ackCount',
  syn_count: 'synCount',
  fin_count: 'finCount',
  urg_count: 'urgCount',
  rst_count: 'rstCount',
  max: 'maxLength',
  min: 'minLength',
  tot_sum: 'sumLength',
  avg: 'avgLength',
  std: 'stdLength',
  mqtt: 'mqtt',
  coap: 'coap',
  http: 'http',
  https: 'https',
  dns: 'dns',
  ssh: 'ssh',
  tcp: 'tcp',
  udp: 'udp',
  arp: 'arp',
  icmp: 'icmp',
  igmp: 'igmp',
  tot_size: 'totSize',
  iat: 'iat',
  magnitue: 'magnitude',  // maps Python misspelling to correct TS field
  magnitude: 'magnitude',
  covariance: 'covariance',
  variance: 'variance',
  flow_idle_time: 'flowIdleTime',
  flow_active_time: 'flowActiveTime',
  predicted_category: 'prediction',
  confidence: 'confidence',
}

export function normalizeFlow(raw: Record<string, unknown>): NetworkFlow {
  // The backend stores per-flow features inside a JSONB `features_json` column.
  // Flatten it so FIELD_MAP can pick up flag numbers, rates, stats, etc.
  const nested =
    raw.features_json && typeof raw.features_json === 'object'
      ? (raw.features_json as Record<string, unknown>)
      : {}
  const flat: Record<string, unknown> = { ...nested, ...raw }

  const mapped: Record<string, unknown> = {}
  for (const [rawKey, tsKey] of Object.entries(FIELD_MAP)) {
    if (rawKey in flat && flat[rawKey] !== null && flat[rawKey] !== undefined) {
      mapped[tsKey] = flat[rawKey]
    }
  }

  if (!mapped.timestamp) {
    mapped.timestamp = new Date().toISOString()
  }

  if ('predicted_category' in flat || 'confidence' in flat) {
    mapped.prediction = {
      category: flat.predicted_category ?? flat.category ?? 'Benign',
      confidence: Number(flat.confidence ?? 0),
    }
  }

  return { ...DEFAULT_FLOW, ...mapped } as NetworkFlow
}
