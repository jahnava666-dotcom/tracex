import React, { useState } from 'react';
import { InfrastructureHop } from '../../types/forensics';
import { Server, ShieldAlert, Info, MapPin, Network } from 'lucide-react';

interface InfrastructureMapProps {
  hops: InfrastructureHop[];
  primaryInfrastructure: {
    ip: string;
    country: string;
    region: string;
    city: string;
    asn: string;
    isp: string;
    hosting: string;
    reverseDns: string;
    coordinates: [number, number];
  };
}

export const InfrastructureMap: React.FC<InfrastructureMapProps> = ({
  hops,
  primaryInfrastructure
}) => {
  const [activeHopIndex, setActiveHopIndex] = useState(0);
  const selectedHop = hops[activeHopIndex] || hops[0] || {
    id: 1,
    step: 'Node 1',
    label: 'Primary MTA',
    ip: primaryInfrastructure.ip,
    country: primaryInfrastructure.country,
    region: primaryInfrastructure.region,
    asn: primaryInfrastructure.asn,
    isp: primaryInfrastructure.isp,
    hostingType: primaryInfrastructure.hosting as any,
    status: 'suspicious',
    timestamp: '10:32:00 UTC',
    latency: '+0ms',
    coordinates: primaryInfrastructure.coordinates
  };

  const hopCount = hops.length;
  const getNodeX = (idx: number) => {
    if (hopCount <= 1) return 400;
    return Math.round(100 + (idx * (600 / (hopCount - 1))));
  };
  const getNodeY = (idx: number) => {
    const yVals = [120, 105, 95, 115, 110];
    return yVals[idx % yVals.length];
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-bold text-slate-900">Infrastructure Intelligence</h2>
          <p className="text-xs text-slate-500">
            Geographic geolocation and Autonomous System Network (ASN) tracing of intermediate hops.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] bg-amber-50 text-amber-700 font-semibold px-2 py-1 rounded-lg border border-amber-200">
            Telemetry: Simulated GeoIP Resolution
          </span>
          <div className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-slate-500 bg-white border border-slate-200 px-2.5 py-1 rounded-lg">
            <Network className="w-3.5 h-3.5 text-blue-600" />
            <span>{hops.length} Network Hops Recorded</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Visual Map Panel + Hop Route + Side Infrastructure Specs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Map & Route Visualization */}
        <div className="lg:col-span-8 space-y-4">
          {/* Interactive World Map Canvas */}
          <div className="relative rounded-2xl border border-slate-200 bg-slate-900 p-6 shadow-sm overflow-hidden text-white min-h-[300px] flex flex-col justify-between">
            {/* Grid & Lat/Long aesthetic overlays */}
            <div className="absolute inset-0 opacity-10 pointer-events-none bg-[radial-gradient(#3b82f6_1px,transparent_1px)] [background-size:16px_16px]"></div>

            <div className="relative z-10 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="flex h-2.5 w-2.5 rounded-full bg-red-500 animate-ping"></span>
                <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300">
                  Global Relay Trajectory (BGP Transit)
                </span>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Lat: {primaryInfrastructure.coordinates[0]}° N • Lon: {primaryInfrastructure.coordinates[1]}° E
              </span>
            </div>

            {/* SVG Stylized Map Layout */}
            <div className="relative z-10 my-6 py-4 flex items-center justify-center">
              <svg className="w-full h-44 text-slate-700" viewBox="0 0 800 240" fill="none">
                {/* World Map Outline Contours (Simplified geo stylization) */}
                <path
                  d="M100 80 Q 150 40, 240 60 T 380 90 T 520 60 T 680 100"
                  stroke="#334155"
                  strokeWidth="1.5"
                  strokeDasharray="4 4"
                />
                <path
                  d="M80 140 Q 200 130, 320 160 T 500 140 T 720 150"
                  stroke="#1e293b"
                  strokeWidth="1.5"
                />

                {/* Animated Connection Beams between hops */}
                {hops.map((hop, idx) => {
                  if (idx === hops.length - 1) return null;
                  const x1 = getNodeX(idx);
                  const y1 = getNodeY(idx);
                  const x2 = getNodeX(idx + 1);
                  const y2 = getNodeY(idx + 1);
                  const midX = (x1 + x2) / 2;
                  const midY = Math.min(y1, y2) - 30;
                  const isMalicious = hop.status === 'malicious' || hops[idx + 1]?.status === 'malicious';
                  const isSuspicious = hop.status === 'suspicious' || hops[idx + 1]?.status === 'suspicious';
                  const strokeColor = isMalicious ? '#ef4444' : isSuspicious ? '#f59e0b' : '#3b82f6';
                  return (
                    <path
                      key={`beam-${idx}`}
                      d={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                      stroke={strokeColor}
                      strokeWidth={isMalicious ? "3" : "2.5"}
                      strokeDasharray={isMalicious ? undefined : "6 4"}
                      className={isMalicious ? "opacity-90" : "opacity-70"}
                    />
                  );
                })}

                {/* Dynamic Hop Markers */}
                {hops.map((hop, idx) => {
                  const cx = getNodeX(idx);
                  const cy = getNodeY(idx);
                  const isSelected = idx === activeHopIndex;
                  const isMalicious = hop.status === 'malicious';
                  const isSuspicious = hop.status === 'suspicious';
                  const fillColor = isMalicious ? '#dc2626' : isSuspicious ? '#f59e0b' : '#3b82f6';
                  const textColor = isMalicious ? '#f87171' : isSuspicious ? '#fbbf24' : '#94a3b8';
                  return (
                    <g key={hop.id || idx} className="cursor-pointer" onClick={() => setActiveHopIndex(idx)}>
                      {isMalicious && (
                        <circle cx={cx} cy={cy} r="14" fill="#ef4444" opacity="0.3" className="animate-ping-slow" />
                      )}
                      <circle
                        cx={cx}
                        cy={cy}
                        r={isSelected ? "9" : "7"}
                        fill={fillColor}
                        stroke={isSelected ? "#ffffff" : undefined}
                        strokeWidth={isSelected ? "2" : undefined}
                      />
                      <text
                        x={cx}
                        y={cy + (idx % 2 === 0 ? 24 : -14)}
                        textAnchor="middle"
                        fill={textColor}
                        fontWeight={isMalicious || isSelected ? "bold" : "normal"}
                        fontSize="11"
                        fontFamily="monospace"
                      >
                        {hop.label} {isMalicious ? '[Flagged]' : ''}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Click to select helper */}
            <div className="relative z-10 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-800 pt-3">
              <span>Interactive Nodes: Click any point to view forensic node telemetry.</span>
              <span className="text-amber-400 font-mono">Selected: {selectedHop.label}</span>
            </div>
          </div>

          {/* Hop Chain Flow Badges */}
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3">
              Server Hop Chain Sequence
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {hops.map((hop, idx) => {
                const isSelected = idx === activeHopIndex;
                const isMalicious = hop.status === 'malicious';
                const isSuspicious = hop.status === 'suspicious';

                return (
                  <React.Fragment key={hop.id}>
                    <button
                      onClick={() => setActiveHopIndex(idx)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                        isSelected
                          ? 'bg-blue-600 text-white shadow-sm ring-2 ring-blue-200'
                          : isMalicious
                          ? 'bg-red-50 text-red-700 border border-red-200 hover:bg-red-100'
                          : isSuspicious
                          ? 'bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100'
                          : 'bg-slate-50 text-slate-700 border border-slate-200 hover:bg-slate-100'
                      }`}
                    >
                      <Server className="w-3.5 h-3.5" />
                      <span>{hop.label}</span>
                    </button>

                    {idx < hops.length - 1 && (
                      <span className="text-slate-400 font-bold text-xs">↓</span>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right: Side Infrastructure Details Panel */}
        <div className="lg:col-span-4 space-y-4">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <MapPin className="w-4 h-4 text-red-500" />
                <span>Node Telemetry</span>
              </h3>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                selectedHop.status === 'malicious' ? 'bg-red-100 text-red-700 border border-red-200' :
                selectedHop.status === 'suspicious' ? 'bg-amber-100 text-amber-700 border border-amber-200' :
                'bg-emerald-100 text-emerald-700 border border-emerald-200'
              }`}>
                {selectedHop.status}
              </span>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">Node Identifier</span>
                <span className="font-semibold text-slate-800">{selectedHop.label}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">IP Address</span>
                <span className="font-mono font-bold text-slate-900">{selectedHop.ip}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">Country</span>
                <span className="font-medium text-slate-800">{selectedHop.country}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">Region / City</span>
                <span className="font-medium text-slate-800">{selectedHop.region}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">ASN</span>
                <span className="font-mono font-medium text-slate-800 text-right max-w-[170px] truncate">{selectedHop.asn}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">Hosting Type</span>
                <span className="font-medium text-slate-800">{selectedHop.hostingType}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-50">
                <span className="text-slate-400">Handoff Latency</span>
                <span className="font-mono text-slate-600">{selectedHop.latency}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Hop Timestamp</span>
                <span className="font-mono text-slate-600">{selectedHop.timestamp}</span>
              </div>
            </div>

            {/* Primary flagged server callout */}
            <div className="rounded-xl bg-red-50 p-3 border border-red-100 text-xs text-red-900 space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
                <span>Bulletproof Relay Identified</span>
              </div>
              <p className="text-[11px] text-red-800/90 leading-relaxed">
                IP {primaryInfrastructure.ip} ({primaryInfrastructure.asn}) has been identified as a high-frequency credential harvesting C2 node.
              </p>
            </div>
          </div>

          {/* Forensic Disclaimer Required by Section 10 */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-3.5 text-[11px] text-slate-600 flex items-start gap-2">
            <Info className="w-4 h-4 text-slate-400 flex-shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong className="text-slate-700">Forensic Disclaimer:</strong> IP geolocation represents infrastructure intelligence and does not prove the physical identity or location of an attacker.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
