import React, { useState } from 'react';
import { ShieldCheck, CheckSquare, Square, AlertCircle, CheckCircle2 } from 'lucide-react';

interface ActionItem {
  id: number;
  action: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  completed?: boolean;
}

interface RecommendedActionsProps {
  initialActions: ActionItem[];
}

export const RecommendedActions: React.FC<RecommendedActionsProps> = ({ initialActions }) => {
  const [actions, setActions] = useState<ActionItem[]>(initialActions);

  const toggleAction = (id: number) => {
    setActions((prev) =>
      prev.map((item) =>
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    );
  };

  const completedCount = actions.filter((a) => a.completed).length;

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
        <div>
          <h2 className="text-base font-bold text-slate-900">Recommended Next Steps</h2>
          <p className="text-xs text-slate-500">
            Standard operating procedure remediation checklist generated for this threat vector.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-600">
            Progress: {completedCount} of {actions.length} resolved
          </span>
          <div className="w-20 h-2 bg-slate-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-600 transition-all duration-300"
              style={{ width: `${(completedCount / actions.length) * 100}%` }}
            />
          </div>
        </div>
      </div>

      <div className="space-y-2.5">
        {actions.map((item) => {
          const isDone = item.completed;
          return (
            <div
              key={item.id}
              onClick={() => toggleAction(item.id)}
              className={`flex items-start gap-3 p-3.5 rounded-xl border transition-all cursor-pointer select-none ${
                isDone
                  ? 'bg-slate-50/60 border-slate-200 opacity-60'
                  : 'bg-white border-slate-200 hover:border-blue-300 hover:bg-blue-50/30 shadow-xs'
              }`}
            >
              <div className="mt-0.5 text-blue-600">
                {isDone ? (
                  <CheckSquare className="w-4 h-4 text-emerald-600" />
                ) : (
                  <Square className="w-4 h-4 text-slate-400" />
                )}
              </div>

              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-400">
                    Step {item.id}.
                  </span>
                  <span
                    className={`text-xs font-medium ${
                      isDone ? 'line-through text-slate-400' : 'text-slate-900'
                    }`}
                  >
                    {item.action}
                  </span>
                </div>
              </div>

              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider ${
                  item.priority === 'Critical'
                    ? 'bg-red-100 text-red-700'
                    : item.priority === 'High'
                    ? 'bg-orange-100 text-orange-700'
                    : 'bg-amber-100 text-amber-700'
                }`}
              >
                {item.priority}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
