import React, { useState } from 'react';
import { EmailInvestigationCase } from '../../types/forensics';
import { Mail, Clock, Paperclip, Link, AlertTriangle, FileCode, Check, Copy } from 'lucide-react';
import { Modal } from '../common/Modal';

interface EmailInfoCardProps {
  caseData: EmailInvestigationCase;
}

export const EmailInfoCard: React.FC<EmailInfoCardProps> = ({ caseData }) => {
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedHeaders, setCopiedHeaders] = useState(false);

  const handleCopyHeaders = () => {
    navigator.clipboard.writeText(caseData.rawHeaders);
    setCopiedHeaders(true);
    setTimeout(() => setCopiedHeaders(false), 2000);
  };

  const isReplyToMismatch = caseData.from !== caseData.replyTo;

  return (
    <>
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 pb-4 mb-4">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
              <Mail className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-slate-900">Email Information</h2>
          </div>

          <button
            onClick={() => setShowRawHeaders(true)}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-slate-50 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-slate-500" />
            <span>Inspect Raw Headers</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          {/* From */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              From (Header)
            </span>
            <div className="font-mono text-slate-900 font-semibold truncate select-all">
              {caseData.from}
            </div>
          </div>

          {/* Reply-To with Mismatch Alert */}
          <div className={`p-3 rounded-xl border ${
            isReplyToMismatch ? 'bg-amber-50/70 border-amber-200' : 'bg-slate-50 border-slate-100'
          }`}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Reply-To
              </span>
              {isReplyToMismatch && (
                <span className="inline-flex items-center gap-1 text-[10px] font-bold text-amber-700 bg-amber-100 px-1.5 py-0.2 rounded">
                  <AlertTriangle className="w-3 h-3" /> Mismatch
                </span>
              )}
            </div>
            <div className="font-mono text-slate-900 font-semibold truncate select-all">
              {caseData.replyTo}
            </div>
          </div>

          {/* Subject */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100 md:col-span-2 lg:col-span-1">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              Subject
            </span>
            <div className="font-semibold text-slate-900 truncate">
              {caseData.subject}
            </div>
          </div>

          {/* Received Time */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              Received Timestamp
            </span>
            <div className="flex items-center gap-1.5 font-mono text-slate-900 font-medium">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>{caseData.receivedTime}</span>
            </div>
          </div>

          {/* Attachment */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              Attachment
            </span>
            <div className="flex items-center gap-1.5 font-mono text-red-600 font-semibold">
              <Paperclip className="w-3.5 h-3.5 text-red-500" />
              <span>{caseData.iocs.attachments[0]?.filename || 'None'}</span>
              <span className="text-[10px] text-slate-400 font-normal">
                ({caseData.iocs.attachments[0]?.size || '0 KB'})
              </span>
            </div>
          </div>

          {/* URLs */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              URLs Detected
            </span>
            <div className="flex items-center gap-1.5 font-medium text-slate-900">
              <Link className="w-3.5 h-3.5 text-blue-500" />
              <span>{caseData.iocs.urls.length} detected</span>
              <span className="text-[10px] text-red-600 font-bold bg-red-50 px-1 rounded">
                1 Malicious
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Raw Headers Modal */}
      <Modal
        isOpen={showRawHeaders}
        onClose={() => setShowRawHeaders(false)}
        title="Raw RFC 822 Email Headers"
        subtitle={`Case ID: ${caseData.caseId} • Forensic Header Snapshot`}
        maxWidth="4xl"
      >
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-500">
              Complete unmanipulated transport headers captured at the corporate gateway.
            </span>
            <button
              onClick={handleCopyHeaders}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors"
            >
              {copiedHeaders ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedHeaders ? 'Copied to Clipboard!' : 'Copy Headers'}</span>
            </button>
          </div>

          <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto max-h-[60vh] leading-relaxed select-all">
            <code>{caseData.rawHeaders}</code>
          </pre>
        </div>
      </Modal>
    </>
  );
};
