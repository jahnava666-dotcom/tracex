import React from 'react';
import { ThreatIntelligenceIndicator } from '../../types/forensics';
import { Database, ShieldAlert, AlertTriangle, CheckCircle2, ExternalLink } from 'lucide-react';

interface ThreatIntelTableProps {
  indicators: ThreatIntelligenceIndicator[];
}

export const ThreatIntelTable: React.FC<ThreatIntelTableProps> = ({ indicators }) => {
  const getReputationBadge = (rep: string) => {
    switch (rep) {
      case 'Malicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-red-100 text-red-800 border border-red-200">
            <ShieldAlert className="w-3 h-3 text-red-600" />
            Malicious
          </span>
        );
      case 'Suspicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
            <AlertTriangle className="w-3 h-3 text-amber-600" />
            Suspicious
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
            Clean
          </span>
        );
    }
  };

  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden space-y-0">
      <div className="p-5 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900">Threat Intelligence</h2>
            <p className="text-xs text-slate-500">
              Cross-referenced against global reputation databases and threat feeds.
            </p>
          </div>
        </div>

        <span className="text-[11px] font-mono text-slate-400">
          Source: TRACE-X Cyber Threat Feed v4.9
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-100">
            <tr>
              <th className="px-5 py-3">Indicator</th>
              <th className="px-5 py-3">Type</th>
              <th className="px-5 py-3">Reputation</th>
              <th className="px-5 py-3">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-slate-700">
            {indicators.map((ind, idx) => (
              <tr key={idx} className="hover:bg-slate-50 transition-colors">
                <td className="px-5 py-3.5 font-mono font-medium text-slate-900 max-w-xs truncate select-all">
                  {ind.indicator}
                </td>

                <td className="px-5 py-3.5">
                  <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] font-bold">
                    {ind.type}
                  </span>
                </td>

                <td className="px-5 py-3.5 whitespace-nowrap">
                  {getReputationBadge(ind.reputation)}
                </td>

                <td className="px-5 py-3.5 text-slate-600 font-normal">
                  {ind.details}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
