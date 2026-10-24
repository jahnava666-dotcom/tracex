import React from 'react';
import { ThreatSignal } from '../../types/forensics';
import {
  UserX,
  ShieldAlert,
  Globe,
  ExternalLink,
  FileArchive,
  AlertTriangle,
  ServerCrash,
  AlertCircle
} from 'lucide-react';

interface ThreatSignalsCardProps {
  signals: ThreatSignal[];
}

export const ThreatSignalsCard: React.FC<ThreatSignalsCardProps> = ({ signals }) => {
  const getIcon = (iconName: string) => {
    switch (iconName) {
      case 'UserX': return UserX;
      case 'ShieldAlert': return ShieldAlert;
      case 'Globe': return Globe;
      case 'ExternalLink': return ExternalLink;
      case 'FileArchive': return FileArchive;
      case 'AlertTriangle': return AlertTriangle;
      case 'ServerCrash': return ServerCrash;
      default: return AlertCircle;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <span className="rounded-full bg-red-100 text-red-700 text-[10px] font-bold px-2 py-0.5 uppercase border border-red-200">Critical</span>;
      case 'high':
        return <span className="rounded-full bg-orange-100 text-orange-700 text-[10px] font-bold px-2 py-0.5 uppercase border border-orange-200">High</span>;
      case 'medium':
        return <span className="rounded-full bg-amber-100 text-amber-700 text-[10px] font-bold px-2 py-0.5 uppercase border border-amber-200">Medium</span>;
      default:
        return <span className="rounded-full bg-slate-100 text-slate-700 text-[10px] font-bold px-2 py-0.5 uppercase border border-slate-200">Low</span>;
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-base font-bold text-slate-900">Threat Detection Signals</h2>
        <p className="text-xs text-slate-500">
          Correlated threat heuristics identifying behavioral, cryptographic, and network anomalies.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {signals.map((sig) => {
          const Icon = getIcon(sig.iconName);
          const isCritical = sig.severity === 'critical';

          return (
            <div
              key={sig.id}
              className={`rounded-2xl border bg-white p-5 shadow-sm transition-all hover:shadow-md flex flex-col justify-between ${
                isCritical ? 'border-red-200/80 bg-gradient-to-b from-white to-red-50/10' : 'border-slate-200'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-xl border ${
                      isCritical ? 'bg-red-50 text-red-600 border-red-100' : 'bg-slate-50 text-slate-700 border-slate-200'
                    }`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-slate-900 leading-snug">{sig.title}</h3>
                      <span className="text-[10px] text-slate-400 font-medium">{sig.category}</span>
                    </div>
                  </div>
                  {getSeverityBadge(sig.severity)}
                </div>

                <p className="mt-3 text-xs text-slate-600 leading-relaxed font-normal">
                  {sig.explanation}
                </p>
              </div>

              {sig.evidence && (
                <div className="mt-3 pt-2.5 border-t border-slate-100">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    Evidence
                  </span>
                  <div className="text-[11px] font-mono text-slate-700 bg-slate-50 p-2 rounded-lg border border-slate-100 break-all">
                    {sig.evidence}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
