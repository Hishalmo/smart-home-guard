import { useEffect } from 'react'
import type { FlowSummary, NetworkFlow, AlertEvent } from '@/types'
import { KpiGrid } from '@/components/dashboard/KpiGrid'
import { TrafficDonut } from '@/components/dashboard/TrafficDonut'
import { ThreatTimeline } from '@/components/dashboard/ThreatTimeline'
import { ProtocolBarChart } from '@/components/dashboard/ProtocolBarChart'
import { TcpFlagRadar } from '@/components/dashboard/TcpFlagRadar'
import { TopSourceIps } from '@/components/dashboard/TopSourceIps'
import { FlowTable } from '@/components/dashboard/FlowTable'
import { AlertFeed } from '@/components/dashboard/AlertFeed'
import { useAlertStore } from '@/store/alertStore'

const mockSummary: FlowSummary = {
  totalFlows: 1204,
  benignCount: 951,
  bruteForceCount: 82,
  reconCount: 115,
  spoofingCount: 56,
  benignPercent: 79.0,
  activeThreats: 253,
  protocolCounts: {
    TCP: 612, UDP: 288, HTTP: 141, HTTPS: 210, DNS: 96,
    MQTT: 64, CoAP: 22, SSH: 19, ARP: 12, ICMP: 7, IGMP: 3,
  },
  topSourceIps: [
    { ip: '192.168.1.42', count: 420 },
    { ip: '192.168.1.10', count: 312 },
    { ip: '10.0.0.5', count: 198 },
    { ip: '192.168.1.1', count: 150 },
    { ip: '192.168.1.88', count: 74 },
  ],
}

const mockTimeline = Array.from({ length: 30 }).map((_, i) => {
  const t = new Date(Date.now() - (29 - i) * 2000).toISOString()
  return {
    timestamp: t,
    benign: 20 + Math.round(Math.random() * 10),
    spoofing: Math.round(Math.random() * 4),
    recon: Math.round(Math.random() * 6),
    bruteForce: Math.round(Math.random() * 3),
  }
})

const mockFlagData = [
  { flag: 'FIN', value: 0.2 },
  { flag: 'SYN', value: 0.9 },
  { flag: 'RST', value: 0.3 },
  { flag: 'PSH', value: 0.4 },
  { flag: 'ACK', value: 0.7 },
  { flag: 'URG', value: 0.05 },
  { flag: 'ECE', value: 0.02 },
  { flag: 'CWR', value: 0.01 },
]

const mockFlows: NetworkFlow[] = [
  {
    id: 'f1', sessionId: 's1', timestamp: new Date().toISOString(),
    sourceIp: '192.168.1.10', destinationIp: '8.8.8.8',
    sourcePort: 52341, destinationPort: 53,
    protocolType: 17, protocolName: 'DNS',
    flowDuration: 0.052, headerLength: 28, rate: 40.1,
    finFlagNumber: 0, synFlagNumber: 0, rstFlagNumber: 0, pshFlagNumber: 0,
    ackFlagNumber: 0, urgFlagNumber: 0, eceFlagNumber: 0, cwrFlagNumber: 0,
    ackCount: 0, synCount: 0, finCount: 0, urgCount: 0, rstCount: 0,
    maxLength: 120, minLength: 80, sumLength: 200, avgLength: 100, stdLength: 20,
    mqtt: 0, coap: 0, http: 0, https: 0, dns: 1, ssh: 0,
    tcp: 0, udp: 1, arp: 0, icmp: 0, igmp: 0,
    totSum: 200, totSize: 200, iat: 0.01, magnitude: 4.1, covariance: 2.2, variance: 1.5,
    flowIdleTime: 0.1, flowActiveTime: 0.05,
    prediction: { category: 'Benign', confidence: 0.98 },
  },
  {
    id: 'f2', sessionId: 's1', timestamp: new Date().toISOString(),
    sourceIp: '10.0.0.5', destinationIp: '192.168.1.1',
    sourcePort: 44112, destinationPort: 22,
    protocolType: 6, protocolName: 'SSH',
    flowDuration: 1.204, headerLength: 32, rate: 920.5,
    finFlagNumber: 0, synFlagNumber: 1, rstFlagNumber: 0, pshFlagNumber: 1,
    ackFlagNumber: 1, urgFlagNumber: 0, eceFlagNumber: 0, cwrFlagNumber: 0,
    ackCount: 5, synCount: 3, finCount: 0, urgCount: 0, rstCount: 0,
    maxLength: 512, minLength: 64, sumLength: 2400, avgLength: 240, stdLength: 90,
    mqtt: 0, coap: 0, http: 0, https: 0, dns: 0, ssh: 1,
    tcp: 1, udp: 0, arp: 0, icmp: 0, igmp: 0,
    totSum: 2400, totSize: 2400, iat: 0.12, magnitude: 8.2, covariance: 5.5, variance: 4.1,
    flowIdleTime: 0.02, flowActiveTime: 1.18,
    prediction: { category: 'BruteForce', confidence: 0.91 },
  },
  {
    id: 'f3', sessionId: 's1', timestamp: new Date().toISOString(),
    sourceIp: '192.168.1.42', destinationIp: '10.0.0.1',
    sourcePort: 50001, destinationPort: 80,
    protocolType: 6, protocolName: 'TCP',
    flowDuration: 0.022, headerLength: 20, rate: 60.0,
    finFlagNumber: 0, synFlagNumber: 1, rstFlagNumber: 0, pshFlagNumber: 0,
    ackFlagNumber: 0, urgFlagNumber: 0, eceFlagNumber: 0, cwrFlagNumber: 0,
    ackCount: 0, synCount: 1, finCount: 0, urgCount: 0, rstCount: 0,
    maxLength: 64, minLength: 64, sumLength: 64, avgLength: 64, stdLength: 0,
    mqtt: 0, coap: 0, http: 0, https: 0, dns: 0, ssh: 0,
    tcp: 1, udp: 0, arp: 0, icmp: 0, igmp: 0,
    totSum: 64, totSize: 64, iat: 0.0, magnitude: 3.5, covariance: 1.0, variance: 0.5,
    flowIdleTime: 0.01, flowActiveTime: 0.01,
    prediction: { category: 'Recon', confidence: 0.84 },
  },
]

const mockAlerts: AlertEvent[] = [
  {
    id: 'a1', sessionId: 's1', timestamp: new Date().toISOString(),
    severity: 'critical', category: 'BruteForce',
    sourceIp: '10.0.0.5', destinationIp: '192.168.1.1',
    message: 'DictionaryBruteForce detected via SSH',
    flowId: 'f2', acknowledged: false,
  },
  {
    id: 'a2', sessionId: 's1', timestamp: new Date(Date.now() - 5000).toISOString(),
    severity: 'medium', category: 'Recon',
    sourceIp: '192.168.1.42', destinationIp: '10.0.0.1',
    message: 'Recon-PortScan detected via TCP',
    flowId: 'f3', acknowledged: false,
  },
]

export function DashboardPage() {
  const pushAlert = useAlertStore((s) => s.pushAlert)
  const clearAlerts = useAlertStore((s) => s.clearAlerts)

  useEffect(() => {
    clearAlerts()
    mockAlerts.forEach(pushAlert)
  }, [pushAlert, clearAlerts])

  return (
    <main className="min-h-screen bg-surface-base p-6 text-content-primary">
      <div className="mx-auto max-w-7xl space-y-6">
        <h1 className="text-2xl font-bold">Dashboard (mock preview)</h1>

        <KpiGrid summary={mockSummary} />

        <div className="grid gap-4 md:grid-cols-2">
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Traffic breakdown</h2>
            <TrafficDonut summary={mockSummary} />
          </section>
          <AlertFeed />
        </div>

        <section className="rounded-md border border-border bg-surface-raised p-4">
          <h2 className="mb-2 text-sm font-semibold">Threat timeline</h2>
          <ThreatTimeline timelineData={mockTimeline} />
        </section>

        <div className="grid gap-4 lg:grid-cols-3">
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Protocols</h2>
            <ProtocolBarChart protocolCounts={mockSummary.protocolCounts} />
          </section>
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">TCP flags</h2>
            <TcpFlagRadar flagData={mockFlagData} />
          </section>
          <section className="rounded-md border border-border bg-surface-raised p-4">
            <h2 className="mb-2 text-sm font-semibold">Top source IPs</h2>
            <TopSourceIps topIps={mockSummary.topSourceIps} />
          </section>
        </div>

        <section className="rounded-md border border-border bg-surface-raised p-4">
          <h2 className="mb-2 text-sm font-semibold">Flows</h2>
          <FlowTable flows={mockFlows} />
        </section>
      </div>
    </main>
  )
}
