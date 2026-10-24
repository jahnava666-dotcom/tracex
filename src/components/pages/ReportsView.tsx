import React, { useState } from 'react';
import { GeneratedReport, EmailInvestigationCase } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';
import { FileText, Download, Eye, Plus, ShieldAlert } from 'lucide-react';
import { ForensicReportModal } from '../investigation/ForensicReportModal';
import { CASE_1024 } from '../../data/mockData';

interface ReportsViewProps {
  reports: GeneratedReport[];
  cases: EmailInvestigationCase[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({ reports, cases }) => {
  const [selectedCaseForReport, setSelectedCaseForReport] = useState<EmailInvestigationCase | null>(null);

  const handleViewReport = (rep: GeneratedReport) => {
    const targetCase = cases.find((c) => c.caseId === rep.caseId) || CASE_1024;
    setSelectedCaseForReport(targetCase);
  };

  const handleDirectDownload = (rep: GeneratedReport) => {
    const targetCase = cases.find((c) => c.caseId === rep.caseId) || CASE_1024;
    const blob = new Blob([
      `TRACE-X INCIDENT REPORT - ${rep.reportId}\nCase: ${rep.caseId}\nVerdict: ${rep.threatLevel} (${rep.riskScore}/100)\nCreated: ${rep.createdAt}\nAuthor: ${rep.author}\n\nSummary:\n${rep.summary}\n`
    ], { type: 'text/plain' });

    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${rep.reportId}_${rep.caseId}.txt`;
    link.click();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Forensic Reports</h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Archived incident summaries and forensic dossiers ready for compliance and security audits.
          </p>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-100">
              <tr>
                <th className="px-5 py-3.5">Report ID</th>
                <th className="px-5 py-3.5">Case ID</th>
                <th className="px-5 py-3.5">Threat Level</th>
                <th className="px-5 py-3.5">Created</th>
                <th className="px-5 py-3.5">Format</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {reports.map((rep) => (
                <tr key={rep.reportId} className="hover:bg-slate-50/80 transition-colors">
                  <td className="px-5 py-4 font-mono font-bold text-slate-900 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-blue-600" />
                    <span>{rep.reportId}</span>
                  </td>

                  <td className="px-5 py-4 font-mono font-medium text-blue-600">
                    {rep.caseId}
                  </td>

                  <td className="px-5 py-4">
                    <RiskBadge verdict={rep.threatLevel} size="sm" />
                  </td>

                  <td className="px-5 py-4 text-slate-500 whitespace-nowrap">
                    {rep.createdAt}
                  </td>

                  <td className="px-5 py-4">
                    <span className="font-mono bg-slate-100 px-2 py-0.5 rounded text-[10px] font-bold text-slate-700">
                      {rep.format}
                    </span>
                  </td>

                  <td className="px-5 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleViewReport(rep)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:text-blue-600 transition-all shadow-xs"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>View</span>
                      </button>
                      <button
                        onClick={() => handleDirectDownload(rep)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 text-xs font-semibold transition-all"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedCaseForReport && (
        <ForensicReportModal
          isOpen={!!selectedCaseForReport}
          onClose={() => setSelectedCaseForReport(null)}
          caseData={selectedCaseForReport}
        />
      )}
    </div>
  );
};
