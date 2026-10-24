import React from 'react';
import { EmailAuthResult } from '../../types/forensics';
import { AuthBadge } from '../common/RiskBadge';
import { ShieldCheck, ShieldAlert, KeyRound, CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';

interface AuthAnalysisCardProps {
  auth: {
    spf: EmailAuthResult;
    dkim: EmailAuthResult;
    dmarc: EmailAuthResult;
  };
}

export const AuthAnalysisCard: React.FC<AuthAnalysisCardProps> = ({ auth }) => {
  const cards = [
    {
      name: 'SPF',
      fullName: 'Sender Policy Framework',
      data: auth.spf,
      icon: ShieldAlert,
      borderClass: auth.spf.status === 'FAIL' ? 'border-red-200 bg-red-50/20' : 'border-slate-200 bg-white'
    },
    {
      name: 'DKIM',
      fullName: 'DomainKeys Identified Mail',
      data: auth.dkim,
      icon: KeyRound,
      borderClass: auth.dkim.status === 'SUSPICIOUS' ? 'border-amber-200 bg-amber-50/20' : 'border-slate-200 bg-white'
    },
    {
      name: 'DMARC',
      fullName: 'Domain-based Message Authentication',
      data: auth.dmarc,
      icon: ShieldCheck,
      borderClass: auth.dmarc.status === 'FAIL' ? 'border-red-200 bg-red-50/20' : 'border-slate-200 bg-white'
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-900">Email Authentication</h2>
          <p className="text-xs text-slate-500">
            Cryptographic and DNS policy evaluation of RFC 5321 / 5322 transport parameters.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {cards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className={`rounded-2xl border ${card.borderClass} p-5 shadow-sm flex flex-col justify-between transition-all hover:shadow-md`}
            >
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-extrabold text-slate-900">{card.name}</span>
                    <span className="text-[10px] text-slate-400 font-medium truncate max-w-[110px]">
                      {card.fullName}
                    </span>
                  </div>
                  <AuthBadge status={card.data.status} />
                </div>

                <div className="mt-3">
                  <p className="text-xs font-semibold text-slate-800">
                    "{card.data.summary}"
                  </p>
                  <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed font-mono bg-slate-50 p-2 rounded-lg border border-slate-100">
                    {card.data.technicalDetails}
                  </p>
                </div>
              </div>

              {card.data.recordFound && (
                <div className="mt-3 pt-2.5 border-t border-slate-100 text-[10px] text-slate-400 font-mono truncate">
                  <span className="font-semibold text-slate-500">DNS:</span> {card.data.recordFound}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
