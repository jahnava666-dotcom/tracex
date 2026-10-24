import React from 'react';
import { Mail, ShieldAlert, AlertTriangle, AlertOctagon, TrendingUp, TrendingDown } from 'lucide-react';

interface StatCardsProps {
  analyzedCount?: number;
  threatsCount?: number;
  highRiskCount?: number;
  criticalCount?: number;
  isRealtimeLive?: boolean;
}

export const StatCards: React.FC<StatCardsProps> = ({
  analyzedCount = 128,
  threatsCount = 34,
  highRiskCount = 17,
  criticalCount = 8,
  isRealtimeLive = false
}) => {
  const cards = [
    {
      title: 'Emails Analyzed',
      value: analyzedCount,
      subtext: '+12% from last week',
      trend: 'up',
      icon: Mail,
      iconBg: 'bg-blue-50 text-blue-600 border-blue-200',
      borderAccent: 'border-l-4 border-l-blue-600',
    },
    {
      title: 'Threats Detected',
      value: threatsCount,
      subtext: '26.5% detection rate',
      trend: 'up',
      icon: ShieldAlert,
      iconBg: 'bg-amber-50 text-amber-600 border-amber-200',
      borderAccent: 'border-l-4 border-l-amber-500',
    },
    {
      title: 'High Risk',
      value: highRiskCount,
      subtext: 'Requires analyst triage',
      trend: 'down',
      icon: AlertTriangle,
      iconBg: 'bg-orange-50 text-orange-600 border-orange-200',
      borderAccent: 'border-l-4 border-l-orange-500',
    },
    {
      title: 'Critical',
      value: criticalCount,
      subtext: 'Immediate action triggered',
      trend: 'up',
      icon: AlertOctagon,
      iconBg: 'bg-red-50 text-red-600 border-red-200',
      borderAccent: 'border-l-4 border-l-red-600',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition-all hover:shadow-md ${card.borderAccent}`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{card.title}</span>
              <div className={`rounded-lg p-2 border ${card.iconBg}`}>
                <Icon className="h-4 w-4" />
              </div>
            </div>

            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-slate-900">{card.value}</span>
            </div>

            <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-500">
              {card.trend === 'up' ? (
                <TrendingUp className="h-3.5 w-3.5 text-red-500" />
              ) : (
                <TrendingDown className="h-3.5 w-3.5 text-emerald-500" />
              )}
              <span>{card.subtext}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
