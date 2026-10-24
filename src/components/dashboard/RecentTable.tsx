import React from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';
import { Eye, ArrowUpRight, ShieldCheck, Mail } from 'lucide-react';

interface RecentTableProps {
  cases: EmailInvestigationCase[];
  onViewCase: (caseItem: EmailInvestigationCase) => void;
  onNavigateToAnalyze?: () => void;
}

export const RecentTable: React.FC<RecentTableProps> = ({
  cases,
  onViewCase,
  onNavigateToAnalyze
}) => {
  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-5 border-b border-slate-100">
        <div>
          <h2 className="text-base font-bold text-slate-900">Recent Investigations</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time forensic telemetry and triage log from corporate mail gateways.
          </p>
        </div>

        {onNavigateToAnalyze && (
          <button
            onClick={onNavigateToAnalyze}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 shadow-sm transition-all"
          >
            <Mail className="h-3.5 w-3.5" />
            <span>Analyze New Email</span>
          </button>
        )}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-100">
            <tr>
              <th className="px-5 py-3">Case ID</th>
              <th className="px-5 py-3">Sender Email</th>
              <th className="px-5 py-3">Risk Score</th>
              <th className="px-5 py-3">Verdict</th>
              <th className="px-5 py-3">Date</th>
              <th className="px-5 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-slate-700">
            {cases.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-slate-400">
                  No investigations recorded yet. Click "Analyze New Email" to start.
                </td>
              </tr>
            ) : (
              cases.map((c) => {
                const isCritical = c.riskScore >= 80;
                const isHigh = c.riskScore >= 60 && c.riskScore < 80;

                return (
                  <tr
                    key={c.caseId}
                    className="hover:bg-slate-50/80 transition-colors group cursor-pointer"
                    onClick={() => onViewCase(c)}
                  >
                    <td className="px-5 py-4 font-mono font-bold text-slate-900 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-blue-600"></span>
                      <span>{c.caseId}</span>
                      {c.isSimulatedDemo ? (
                        <span className="text-[9px] bg-slate-100 text-slate-500 font-semibold px-1 py-0.5 rounded border border-slate-200">
                          DEMO
                        </span>
                      ) : (
                        <span className="text-[9px] bg-blue-50 text-blue-700 font-semibold px-1 py-0.5 rounded border border-blue-200">
                          LIVE
                        </span>
                      )}
                    </td>

                  <td className="px-5 py-4">
                    <div className="font-medium text-slate-800">{c.email}</div>
                    <div className="text-[11px] text-slate-400 line-clamp-1 max-w-xs">{c.subject}</div>
                  </td>

                  <td className="px-5 py-4">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono font-bold ${
                        isCritical ? 'text-red-600' : isHigh ? 'text-orange-600' : 'text-emerald-600'
                      }`}>
                        {c.riskScore}/100
                      </span>
                      {/* Mini bar */}
                      <div className="w-16 h-1.5 bg-slate-100 rounded-full overflow-hidden hidden sm:block">
                        <div
                          className={`h-full rounded-full ${
                            isCritical ? 'bg-red-500' : isHigh ? 'bg-orange-500' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${c.riskScore}%` }}
                        />
                      </div>
                    </div>
                  </td>

                  <td className="px-5 py-4">
                    <RiskBadge verdict={c.verdict} size="sm" />
                  </td>

                  <td className="px-5 py-4 text-slate-500 whitespace-nowrap">
                    {c.date.split(',')[0]}
                  </td>

                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onViewCase(c);
                      }}
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:text-blue-600 hover:border-blue-200 shadow-sm transition-all"
                    >
                      <Eye className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-600" />
                      <span>View</span>
                    </button>
                  </td>
                </tr>
              );
            }))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
