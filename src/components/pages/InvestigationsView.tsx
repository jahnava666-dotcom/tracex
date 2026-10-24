import React, { useState } from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';
import { Search, Filter, Eye, Trash2, AlertTriangle, ChevronDown } from 'lucide-react';

interface InvestigationsViewProps {
  cases: EmailInvestigationCase[];
  onViewCase: (c: EmailInvestigationCase) => void;
  onDeleteCase?: (caseId: string) => Promise<void> | void;
  onUpdateStatus?: (caseId: string, newStatus: 'Open' | 'Under Review' | 'Mitigated' | 'Closed') => Promise<void> | void;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({
  cases,
  onViewCase,
  onDeleteCase,
  onUpdateStatus
}) => {
  const [filterVerdict, setFilterVerdict] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [caseToDelete, setCaseToDelete] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [statusMenuOpen, setStatusMenuOpen] = useState<string | null>(null);

  const filterOptions = ['All', 'Safe', 'Suspicious', 'High Risk', 'Critical'];
  const statusOptions: Array<'Open' | 'Under Review' | 'Mitigated' | 'Closed'> = [
    'Open',
    'Under Review',
    'Mitigated',
    'Closed'
  ];

  const filteredCases = cases.filter((c) => {
    // Verdict filter
    if (filterVerdict === 'Safe' && c.verdict !== 'Likely Safe') return false;
    if (filterVerdict === 'Suspicious' && c.verdict !== 'Suspicious') return false;
    if (filterVerdict === 'High Risk' && c.verdict !== 'High Risk') return false;
    if (filterVerdict === 'Critical' && c.verdict !== 'Critical Threat') return false;

    // Search query filter (Case ID, Email, Domain, IP)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = c.caseId.toLowerCase().includes(q);
      const matchEmail = c.email?.toLowerCase().includes(q) || false;
      const matchDomain =
        c.primaryInfrastructure?.reverseDns?.toLowerCase().includes(q) ||
        c.from?.toLowerCase().includes(q) ||
        false;
      const matchIp = c.primaryInfrastructure?.ip?.toLowerCase().includes(q) || false;
      return matchId || matchEmail || matchDomain || matchIp;
    }

    return true;
  });

  const confirmDelete = async () => {
    if (!caseToDelete || !onDeleteCase) return;
    setIsDeleting(true);
    await onDeleteCase(caseToDelete);
    setIsDeleting(false);
    setCaseToDelete(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Investigations Archive</h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Historical repository of parsed email incidents, threat scorings, and SOC case logs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-semibold">
            {filteredCases.length} incident{filteredCases.length === 1 ? '' : 's'} indexed
          </span>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mr-2 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Verdict:
          </span>
          {filterOptions.map((opt) => (
            <button
              key={opt}
              onClick={() => setFilterVerdict(opt)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                filterVerdict === opt
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {opt}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative min-w-[280px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Case ID, Email, Domain, or IP..."
            className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100 transition-all"
          />
        </div>
      </div>

      {/* Cases Table */}
      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-100">
              <tr>
                <th className="px-5 py-3.5">Case ID</th>
                <th className="px-5 py-3.5">Date</th>
                <th className="px-5 py-3.5">Email Sender</th>
                <th className="px-5 py-3.5">Risk Score</th>
                <th className="px-5 py-3.5">Verdict</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-12 text-center text-slate-400">
                    No investigations match the selected filter criteria.
                  </td>
                </tr>
              ) : (
                filteredCases.map((c) => (
                  <tr
                    key={c.caseId}
                    className="hover:bg-slate-50/80 transition-colors cursor-pointer"
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

                    <td className="px-5 py-4 text-slate-500 whitespace-nowrap">
                      {c.date}
                    </td>

                    <td className="px-5 py-4">
                      <div className="font-semibold text-slate-800">{c.email}</div>
                      <div className="text-[11px] text-slate-400 truncate max-w-xs">{c.subject}</div>
                    </td>

                    <td className="px-5 py-4 font-mono font-bold">
                      <span
                        className={
                          c.riskScore >= 80
                            ? 'text-red-600'
                            : c.riskScore >= 60
                            ? 'text-orange-600'
                            : 'text-emerald-600'
                        }
                      >
                        {c.riskScore}/100
                      </span>
                    </td>

                    <td className="px-5 py-4">
                      <RiskBadge verdict={c.verdict} size="sm" />
                    </td>

                    <td className="px-5 py-4" onClick={(e) => e.stopPropagation()}>
                      <div className="relative inline-block">
                        <button
                          onClick={() =>
                            setStatusMenuOpen(statusMenuOpen === c.caseId ? null : c.caseId)
                          }
                          className="inline-flex items-center gap-1 rounded-md bg-slate-100 hover:bg-slate-200 px-2 py-0.5 text-[10px] font-semibold text-slate-700 uppercase transition-colors"
                        >
                          <span>{c.status || 'Open'}</span>
                          <ChevronDown className="w-2.5 h-2.5 text-slate-500" />
                        </button>

                        {statusMenuOpen === c.caseId && (
                          <div className="absolute left-0 mt-1 w-32 rounded-lg border border-slate-200 bg-white shadow-lg p-1 z-20">
                            {statusOptions.map((st) => (
                              <button
                                key={st}
                                onClick={async () => {
                                  setStatusMenuOpen(null);
                                  if (onUpdateStatus) await onUpdateStatus(c.caseId, st);
                                }}
                                className={`w-full text-left px-2 py-1 text-[11px] rounded font-semibold transition-colors ${
                                  c.status === st ? 'bg-blue-50 text-blue-700' : 'hover:bg-slate-50 text-slate-700'
                                }`}
                              >
                                {st}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </td>

                    <td className="px-5 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => onViewCase(c)}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:text-blue-600 hover:border-blue-200 shadow-sm transition-all"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>View</span>
                        </button>

                        {onDeleteCase && (
                          <button
                            onClick={() => setCaseToDelete(c.caseId)}
                            className="inline-flex items-center p-1.5 rounded-lg border border-slate-200 text-slate-400 hover:text-red-600 hover:bg-red-50 hover:border-red-200 shadow-xs transition-all"
                            title="Delete case record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {caseToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
            <div className="flex items-center gap-3 text-red-600 mb-3">
              <div className="h-10 w-10 rounded-xl bg-red-100 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900">Delete Investigation</h3>
            </div>
            <p className="text-xs text-slate-600 mb-5 leading-relaxed">
              Are you sure you want to permanently delete case <span className="font-mono font-bold text-slate-900">{caseToDelete}</span>? This will also purge associated indicators and evidence links.
            </p>

            <div className="flex items-center justify-end gap-2 text-xs">
              <button
                disabled={isDeleting}
                onClick={() => setCaseToDelete(null)}
                className="px-4 py-2 rounded-xl border border-slate-200 font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
              >
                Cancel
              </button>
              <button
                disabled={isDeleting}
                onClick={confirmDelete}
                className="px-4 py-2 rounded-xl bg-red-600 font-bold text-white shadow-sm hover:bg-red-700 disabled:opacity-50 transition-all cursor-pointer"
              >
                {isDeleting ? 'Deleting...' : 'Delete Incident'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
