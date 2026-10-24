import React from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { StatCards } from './StatCards';
import { RecentTable } from './RecentTable';
import { Shield, Sparkles, Mail, Database, Activity } from 'lucide-react';
import { DashboardStats } from '../../services/statsService';

interface DashboardViewProps {
  cases: EmailInvestigationCase[];
  onViewCase: (c: EmailInvestigationCase) => void;
  onNavigateToAnalyze: () => void;
  stats?: DashboardStats;
  isDemoFallback?: boolean;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  cases,
  onViewCase,
  onNavigateToAnalyze,
  stats,
  isDemoFallback = false
}) => {
  const dynamicAnalyzed = stats?.analyzedCount ?? (cases.length > 0 ? cases.length : 128);
  const dynamicThreats =
    stats?.threatsCount ?? cases.filter((c) => c.verdict !== 'Likely Safe').length;
  const dynamicHigh =
    stats?.highRiskCount ?? cases.filter((c) => c.verdict === 'High Risk').length;
  const dynamicCritical =
    stats?.criticalCount ?? cases.filter((c) => c.verdict === 'Critical Threat').length;

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 font-mono">
              SOC Mail Gateway • Real-Time Supabase Protection
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight mt-1">
            Security Investigation Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Real-time mailbox telemetry, forensic extraction, and threat classification stream.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {isDemoFallback ? (
            <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-amber-600" />
              <span>Simulated Demo Baseline</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-semibold">
              <Database className="w-3.5 h-3.5 text-emerald-600" />
              <span>Live Postgres Telemetry</span>
            </div>
          )}

          <button
            onClick={onNavigateToAnalyze}
            className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-xs sm:text-sm font-bold text-white shadow-lg shadow-blue-600/20 hover:bg-blue-700 transition-all hover:scale-[1.01] cursor-pointer"
          >
            <Mail className="h-4 w-4" />
            <span>Analyze Email</span>
          </button>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <StatCards
        analyzedCount={dynamicAnalyzed}
        threatsCount={dynamicThreats}
        highRiskCount={dynamicHigh}
        criticalCount={dynamicCritical}
        isRealtimeLive={stats?.isRealtimeLive ?? !isDemoFallback}
      />

      {/* Recent Investigations Table */}
      <RecentTable
        cases={cases}
        onViewCase={onViewCase}
        onNavigateToAnalyze={onNavigateToAnalyze}
      />
    </div>
  );
};
