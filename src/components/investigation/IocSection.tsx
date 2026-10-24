import React, { useState } from 'react';
import { IOCCollection } from '../../types/forensics';
import { ShieldAlert, Copy, Check, Terminal, ExternalLink, Globe, Server, Link2, Paperclip } from 'lucide-react';

interface IocSectionProps {
  iocs: IOCCollection;
  caseId: string;
}

export const IocSection: React.FC<IocSectionProps> = ({ iocs, caseId }) => {
  const [copied, setCopied] = useState(false);

  const getFormattedIocs = () => {
    return `# TRACE-X Forensic IOC Export - ${caseId}
# Generated: ${new Date().toISOString()}

[DOMAINS]
${iocs.domains.join('\n')}

[IPS]
${iocs.ips.join('\n')}

[URLS]
${iocs.urls.join('\n')}

[ATTACHMENTS]
${iocs.attachments.map((a) => `${a.filename} | SHA256: ${a.sha256}`).join('\n')}
`;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getFormattedIocs());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-900">Indicators of Compromise</h2>
          <p className="text-xs text-slate-500">
            Actionable network and host artifacts extracted from this case for firewall and SIEM blocking.
          </p>
        </div>

        <button
          onClick={handleCopy}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm shadow-blue-500/20 transition-all active:scale-95"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'IOCs Copied to Clipboard!' : 'Copy IOCs'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Domains */}
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500">
            <Globe className="w-3.5 h-3.5 text-blue-600" />
            <span>Domains ({iocs.domains.length})</span>
          </div>
          <div className="space-y-1">
            {iocs.domains.map((dom, i) => (
              <div key={i} className="font-mono text-xs text-slate-800 bg-white p-2 rounded-lg border border-slate-200 select-all truncate">
                {dom}
              </div>
            ))}
          </div>
        </div>

        {/* IPs */}
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500">
            <Server className="w-3.5 h-3.5 text-indigo-600" />
            <span>IPs ({iocs.ips.length})</span>
          </div>
          <div className="space-y-1">
            {iocs.ips.map((ip, i) => (
              <div key={i} className="font-mono text-xs text-slate-800 bg-white p-2 rounded-lg border border-slate-200 select-all truncate">
                {ip}
              </div>
            ))}
          </div>
        </div>

        {/* URLs */}
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500">
            <Link2 className="w-3.5 h-3.5 text-red-600" />
            <span>URLs ({iocs.urls.length})</span>
          </div>
          <div className="space-y-1">
            {iocs.urls.map((url, i) => (
              <div key={i} className="font-mono text-xs text-slate-800 bg-white p-2 rounded-lg border border-slate-200 select-all truncate" title={url}>
                {url}
              </div>
            ))}
          </div>
        </div>

        {/* Attachments */}
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500">
            <Paperclip className="w-3.5 h-3.5 text-amber-600" />
            <span>Attachments ({iocs.attachments.length})</span>
          </div>
          <div className="space-y-1">
            {iocs.attachments.map((att, i) => (
              <div key={i} className="text-xs text-slate-800 bg-white p-2 rounded-lg border border-slate-200">
                <div className="font-mono font-bold text-red-600 truncate">{att.filename}</div>
                <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">
                  {att.sha256.substring(0, 16)}...
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
