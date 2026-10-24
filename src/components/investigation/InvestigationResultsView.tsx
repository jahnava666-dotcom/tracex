import React, { useState } from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { InvestigationHeader } from './InvestigationHeader';
import { EmailInfoCard } from './EmailInfoCard';
import { AuthAnalysisCard } from './AuthAnalysisCard';
import { ThreatSignalsCard } from './ThreatSignalsCard';
import { InfrastructureMap } from './InfrastructureMap';
import { ForensicTimeline } from './ForensicTimeline';
import { ThreatIntelTable } from './ThreatIntelTable';
import { IocSection } from './IocSection';
import { AiAssistantPanel } from './AiAssistantPanel';
import { RecommendedActions } from './RecommendedActions';
import { ForensicReportModal } from './ForensicReportModal';
import { FileText, ShieldAlert, Download, Share2, Printer } from 'lucide-react';

interface InvestigationResultsViewProps {
  caseData: EmailInvestigationCase;
  onBackToDashboard: () => void;
}

export const InvestigationResultsView: React.FC<InvestigationResultsViewProps> = ({
  caseData,
  onBackToDashboard
}) => {
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [reportModalMode, setReportModalMode] = useState<'full' | 'iocs'>('full');

  const handleOpenFullReport = () => {
    setReportModalMode('full');
    setIsReportModalOpen(true);
  };

  const handleOpenIocExport = () => {
    setReportModalMode('iocs');
    setIsReportModalOpen(true);
  };

  return (
    <div className="space-y-8 pb-12">
      {/* 1. Score & Case Header */}
      <InvestigationHeader
        caseData={caseData}
        onBackToDashboard={onBackToDashboard}
        onOpenReportModal={handleOpenFullReport}
      />

      {/* 2. Email Information Card */}
      <EmailInfoCard caseData={caseData} />

      {/* 3. Authentication Analysis (SPF / DKIM / DMARC) */}
      <AuthAnalysisCard auth={caseData.auth} />

      {/* 4. Threat Detection Signals */}
      <ThreatSignalsCard signals={caseData.signals} />

      {/* 5. Infrastructure Intelligence / Geo Map */}
      <InfrastructureMap
        hops={caseData.infrastructureHops}
        primaryInfrastructure={caseData.primaryInfrastructure}
      />

      {/* 6. Forensic Timeline */}
      {caseData.timeline.length > 0 && (
        <ForensicTimeline timeline={caseData.timeline} />
      )}

      {/* 7. Threat Intelligence Table */}
      {caseData.threatIntel.length > 0 && (
        <ThreatIntelTable indicators={caseData.threatIntel} />
      )}

      {/* 8. IOC Section */}
      <IocSection iocs={caseData.iocs} caseId={caseData.caseId} />

      {/* 9. AI Investigation Assistant & Recommended Actions Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6">
          <AiAssistantPanel caseData={caseData} />
        </div>
        <div className="lg:col-span-6">
          <RecommendedActions initialActions={caseData.recommendedActions} />
        </div>
      </div>

      {/* 10. Generate Forensic Report & Export Buttons (Section 16 requirement) */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-900">Incident Dossier & Evidence Export</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Compile this investigation into an audit-compliant forensic report or machine-readable IOC package.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
          <button
            onClick={handleOpenIocExport}
            className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-3 text-xs font-bold text-slate-700 hover:bg-slate-50 hover:border-slate-300 shadow-sm transition-all"
          >
            <ShieldAlert className="w-4 h-4 text-blue-600" />
            <span>Export IOC Report</span>
          </button>

          <button
            onClick={handleOpenFullReport}
            className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-xs font-bold text-white shadow-lg shadow-blue-600/25 hover:bg-blue-700 transition-all"
          >
            <FileText className="w-4 h-4" />
            <span>Generate Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Report Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        caseData={caseData}
        mode={reportModalMode}
      />
    </div>
  );
};
