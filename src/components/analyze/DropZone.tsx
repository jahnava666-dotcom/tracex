import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, Sparkles, ShieldAlert, AlertCircle, FileCode, CheckCircle2 } from 'lucide-react';

interface DropZoneProps {
  onStartAnalysis: (file?: File, rawText?: string, isDemo?: boolean) => void;
  onUseDemo: () => void;
}

export const DropZone: React.FC<DropZoneProps> = ({ onStartAnalysis, onUseDemo }) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [pastedHeaders, setPastedHeaders] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const triggerAnalysis = () => {
    if (activeTab === 'upload' && selectedFile) {
      onStartAnalysis(selectedFile);
    } else if (activeTab === 'paste' && pastedHeaders.trim()) {
      onStartAnalysis(undefined, pastedHeaders);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-semibold border border-blue-200">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Automated Mail Sandbox & Triage</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
          Analyze Suspicious Email
        </h1>
        <p className="text-sm text-slate-500 max-w-lg mx-auto">
          Upload a suspicious email to begin forensic analysis. Extract authentication headers, detect evasive IOCs, and trace infrastructure hops.
        </p>
      </div>

      {/* Mode Switcher */}
      <div className="flex justify-center">
        <div className="inline-flex p-1 bg-slate-100 rounded-xl border border-slate-200 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'upload'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            File Upload (EML / MSG)
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'paste'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Paste Raw Headers
          </button>
        </div>
      </div>

      {/* Main Container */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm">
        {activeTab === 'upload' ? (
          <div>
            {/* Drag and Drop Zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-2xl p-8 sm:p-12 text-center cursor-pointer transition-all ${
                isDragOver
                  ? 'border-blue-500 bg-blue-50/60 scale-[1.005]'
                  : selectedFile
                  ? 'border-emerald-400 bg-emerald-50/30'
                  : 'border-slate-300 bg-slate-50/50 hover:bg-slate-50 hover:border-slate-400'
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".eml,.msg,.txt,.rfc822"
                className="hidden"
              />

              <div className="flex flex-col items-center">
                {selectedFile ? (
                  <div className="flex flex-col items-center">
                    <div className="h-14 w-14 rounded-2xl bg-emerald-100 text-emerald-600 flex items-center justify-center mb-3">
                      <CheckCircle2 className="w-8 h-8" />
                    </div>
                    <span className="text-sm font-bold text-slate-800">{selectedFile.name}</span>
                    <span className="text-xs text-slate-500 mt-0.5">
                      {(selectedFile.size / 1024).toFixed(1)} KB • Ready for forensic parsing
                    </span>
                    <span className="mt-3 text-xs font-semibold text-blue-600 hover:underline">
                      Click to choose a different file
                    </span>
                  </div>
                ) : (
                  <>
                    <div className="h-14 w-14 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center mb-4 border border-blue-100 shadow-sm">
                      <UploadCloud className="w-7 h-7" />
                    </div>
                    <h3 className="text-base font-bold text-slate-900">
                      Drop your email here
                    </h3>
                    <p className="text-xs text-slate-500 mt-1">
                      Drag & drop your suspicious file to initiate deep inspection
                    </p>

                    <div className="mt-4 flex items-center gap-2 text-[11px] font-mono font-medium text-slate-500 bg-white px-3 py-1.5 rounded-lg border border-slate-200">
                      <span>Supported formats:</span>
                      <span className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-bold">EML</span>
                      <span className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-bold">MSG</span>
                      <span className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-bold">Raw Email Headers</span>
                    </div>

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        fileInputRef.current?.click();
                      }}
                      className="mt-6 rounded-xl bg-white border border-slate-300 px-5 py-2.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 shadow-sm transition-all"
                    >
                      Choose File
                    </button>
                  </>
                )}
              </div>
            </div>

            {selectedFile && (
              <div className="mt-5 text-center">
                <button
                  onClick={triggerAnalysis}
                  className="rounded-xl bg-blue-600 px-8 py-3 text-sm font-bold text-white shadow-lg shadow-blue-600/25 hover:bg-blue-700 transition-all"
                >
                  Analyze Uploaded File
                </button>
              </div>
            )}
          </div>
        ) : (
          /* Raw Header Paste Zone */
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-600 mb-1.5">
                Paste RFC 822 Email Headers
              </label>
              <textarea
                value={pastedHeaders}
                onChange={(e) => setPastedHeaders(e.target.value)}
                placeholder={`Delivered-To: analyst@company.com\nReceived: from unknown-vps.org (185.220.101.42)...\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\nFrom: "Security Alert" <security@secure-login-example.com>\nSubject: Urgent Account Verification Required...`}
                rows={10}
                className="w-full rounded-xl border border-slate-200 bg-slate-50 p-4 font-mono text-xs text-slate-800 placeholder-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all"
              />
            </div>
            <div className="flex justify-end">
              <button
                disabled={!pastedHeaders.trim()}
                onClick={triggerAnalysis}
                className="rounded-xl bg-blue-600 px-6 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                Analyze Raw Headers
              </button>
            </div>
          </div>
        )}

        {/* OR Divider */}
        <div className="relative my-8 text-center">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-slate-200" />
          </div>
          <span className="relative bg-white px-4 text-xs font-bold uppercase tracking-widest text-slate-400">
            OR
          </span>
        </div>

        {/* Demo Button */}
        <div className="text-center">
          <button
            onClick={onUseDemo}
            className="group w-full sm:w-auto inline-flex items-center justify-center gap-2.5 rounded-xl border border-blue-200 bg-blue-50/70 px-7 py-3 text-sm font-bold text-blue-700 shadow-sm hover:bg-blue-100 hover:border-blue-300 transition-all"
          >
            <Sparkles className="w-4 h-4 text-blue-600 group-hover:scale-110 transition-transform" />
            <span>Use Demo Email</span>
          </button>
          <p className="text-xs text-slate-500 mt-2">
            Loads a realistic credential phishing & malicious ZIP investigation (CASE-1024) instantly.
          </p>
        </div>
      </div>

      {/* Forensic Authorization Warning */}
      <div className="flex items-start gap-2.5 rounded-xl border border-amber-200 bg-amber-50/60 p-4 text-xs text-amber-900">
        <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold">Security Compliance Notice:</span> Only analyze emails you are authorized to investigate in accordance with organizational data governance and privacy policies.
        </div>
      </div>
    </div>
  );
};
