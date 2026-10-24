import React from 'react';
import { ThreatVerdict, AuthStatus } from '../../types/forensics';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertOctagon, CheckCircle2, XCircle } from 'lucide-react';

interface RiskBadgeProps {
  verdict: ThreatVerdict;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ verdict, size = 'md', showIcon = true }) => {
  const styles = {
    'Likely Safe': {
      bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      icon: CheckCircle2,
      dot: 'bg-emerald-500',
    },
    'Suspicious': {
      bg: 'bg-amber-50 text-amber-700 border-amber-200',
      icon: AlertTriangle,
      dot: 'bg-amber-500',
    },
    'High Risk': {
      bg: 'bg-orange-50 text-orange-700 border-orange-200',
      icon: ShieldAlert,
      dot: 'bg-orange-500',
    },
    'Critical Threat': {
      bg: 'bg-red-50 text-red-700 border-red-200',
      icon: AlertOctagon,
      dot: 'bg-red-500',
    }
  }[verdict] || {
    bg: 'bg-slate-100 text-slate-700 border-slate-200',
    icon: ShieldCheck,
    dot: 'bg-slate-500',
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1.5 font-medium',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold tracking-wide'
  }[size];

  const IconComponent = styles.icon;

  return (
    <span className={`inline-flex items-center rounded-full border ${styles.bg} ${sizeClasses} shadow-sm transition-all`}>
      {showIcon && <IconComponent className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
      <span>{verdict.toUpperCase()}</span>
    </span>
  );
};

export const AuthBadge: React.FC<{ status: AuthStatus }> = ({ status }) => {
  if (status === 'PASS') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
        PASS
      </span>
    );
  }
  if (status === 'FAIL') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-800 border border-red-200">
        <XCircle className="w-3.5 h-3.5 text-red-600" />
        FAIL
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200">
      <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
      SUSPICIOUS
    </span>
  );
};
