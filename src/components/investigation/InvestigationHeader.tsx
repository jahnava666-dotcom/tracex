import React from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';
import { ShieldAlert, AlertOctagon, Share2, Printer, ArrowLeft, Download } from 'lucide-react';

interface InvestigationHeaderProps {
  caseData: EmailInvestigationCase;
  onBackToDashboard: () => void;
  onOpenReportModal: () => void;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  caseData,
  onBackToDashboard,
  onOpenReportModal
}) => {
  const { caseId, verdict, riskScore, date, assignedAnalyst } = caseData;

  // Signal breakdown items according to requirement 6
  const scoreSignals = [
    { label: 'Sender Spoofing', points: 20, color: 'bg-red-500' },
    { label: 'DMARC Failure', points: 15, color: 'bg-red-500' },
    { label: 'Suspicious Domain', points: 15, color: 'bg-orange-500' },
    { label: 'Malicious URL', points: 20, color: 'bg-red-500' },
    { label: 'Suspicious Attachment', points: 10, color: 'bg-amber-500' },
    { label: 'Urgency Language', points: 7, color: 'bg-blue-500' },
  ];

  // SVG Circular Meter calculations
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (riskScore / 100) * circumference;

  return (
    <div className="space-y-6">
      {/* Top back & action navigation */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <button
          onClick={onBackToDashboard}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Dashboard</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-all shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Dossier</span>
          </button>

          <button
            onClick={onOpenReportModal}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-blue-600 text-xs font-semibold text-white hover:bg-blue-700 transition-all shadow-sm shadow-blue-500/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Generate Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Main Score Hero Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Left: Case Info & Verdict */}
          <div className="lg:col-span-4 space-y-4">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-sm font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                  {caseId}
                </span>
                {caseData.isSimulatedDemo ? (
                  <span className="text-[10px] bg-amber-50 text-amber-700 font-bold px-2 py-0.5 rounded border border-amber-200 uppercase">
                    Simulated Demo Scenario
                  </span>
                ) : (
                  <span className="text-[10px] bg-emerald-50 text-emerald-700 font-bold px-2 py-0.5 rounded border border-emerald-200 uppercase">
                    Live Analysis
                  </span>
                )}
                <span className="text-xs text-slate-400">• {date}</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 mt-2 tracking-tight">
                Investigation Results
              </h1>
              <p className="text-xs text-slate-500 mt-1">
                Forensic dossier compiled by {assignedAnalyst}
              </p>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1">
                Final Threat Verdict
              </div>
              <RiskBadge verdict={verdict} size="lg" />
            </div>

            <p className="text-xs text-slate-600 leading-relaxed bg-slate-50 p-3 rounded-xl border border-slate-100">
              {caseData.summary}
            </p>
          </div>

          {/* Center: Large Circular Risk Score Visualization */}
          <div className="lg:col-span-4 flex flex-col items-center justify-center p-4 border-y lg:border-y-0 lg:border-x border-slate-100">
            <div className="relative flex items-center justify-center">
              <svg className="w-44 h-44 transform -rotate-90">
                {/* Background Track */}
                <circle
                  cx="88"
                  cy="88"
                  r={radius}
                  stroke="#f1f5f9"
                  strokeWidth="12"
                  fill="transparent"
                />
                {/* Score Arc */}
                <circle
                  cx="88"
                  cy="88"
                  r={radius}
                  stroke={riskScore >= 80 ? '#dc2626' : riskScore >= 60 ? '#ea580c' : riskScore >= 30 ? '#f59e0b' : '#10b981'}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>

              {/* Score Value in Center */}
              <div className="absolute flex flex-col items-center text-center">
                <span className="text-4xl font-black text-slate-900 tracking-tight">
                  {riskScore}
                </span>
                <span className="text-xs font-mono font-bold text-slate-400">/ 100</span>
                <span className={`text-[11px] font-bold uppercase mt-0.5 ${
                  riskScore >= 80 ? 'text-red-600' : 'text-orange-600'
                }`}>
                  Risk Score
                </span>
              </div>
            </div>

            {/* Risk Scale Legend */}
            <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-500 font-medium">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>0–29: Likely Safe</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span>30–59: Suspicious</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                <span>60–79: High Risk</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-600 font-semibold text-red-600">
                  80–100: Critical Threat
                </span>
              </div>
            </div>
          </div>

          {/* Right: Signal Breakdown Contributions */}
          <div className="lg:col-span-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-700">
                Risk Signal Breakdown
              </span>
              <span className="text-[11px] font-mono text-slate-400">Illustrative Weights</span>
            </div>

            <div className="space-y-2">
              {scoreSignals.map((signal, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium">{signal.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-900">+{signal.points}</span>
                    <div className="w-12 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${signal.color}`}
                        style={{ width: `${(signal.points / 20) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-slate-900">
              <span>Cumulative Risk Score</span>
              <span className="font-mono text-red-600 font-black text-sm">{riskScore}/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
