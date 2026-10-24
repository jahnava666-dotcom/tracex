import React from 'react';
import { ForensicTimelineEvent } from '../../types/forensics';
import { Clock, ShieldAlert, CheckCircle2, AlertTriangle, ArrowDown } from 'lucide-react';

interface ForensicTimelineProps {
  timeline: ForensicTimelineEvent[];
}

export const ForensicTimeline: React.FC<ForensicTimelineProps> = ({ timeline }) => {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-900">Forensic Timeline</h2>
          <p className="text-xs text-slate-500">
            Chronological reconstruction of message creation, intermediate relays, and corporate gateway ingestion.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
          <Clock className="w-3.5 h-3.5" />
          <span>Total Transit: 11 seconds</span>
        </div>
      </div>

      {/* Vertical timeline */}
      <div className="relative pl-6 sm:pl-8 space-y-8 before:absolute before:left-3 sm:before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
        {timeline.map((event, idx) => {
          const isAlert = event.status === 'alert';
          const isFlagged = event.status === 'flagged';

          return (
            <div key={event.id} className="relative group">
              {/* Timeline marker icon */}
              <div
                className={`absolute -left-6 sm:-left-8 top-0.5 flex h-6 w-6 sm:h-8 sm:w-8 items-center justify-center rounded-full border-2 bg-white transition-transform group-hover:scale-110 ${
                  isAlert
                    ? 'border-red-500 text-red-600 ring-4 ring-red-50'
                    : isFlagged
                    ? 'border-amber-500 text-amber-600 ring-4 ring-amber-50'
                    : 'border-blue-500 text-blue-600 ring-4 ring-blue-50'
                }`}
              >
                {isAlert ? (
                  <ShieldAlert className="h-3 w-3 sm:h-4 sm:w-4" />
                ) : isFlagged ? (
                  <AlertTriangle className="h-3 w-3 sm:h-4 sm:w-4" />
                ) : (
                  <CheckCircle2 className="h-3 w-3 sm:h-4 sm:w-4" />
                )}
              </div>

              {/* Event Card */}
              <div
                className={`rounded-xl border p-4 text-xs transition-all ${
                  isAlert
                    ? 'border-red-200 bg-red-50/30'
                    : isFlagged
                    ? 'border-amber-200 bg-amber-50/20'
                    : 'border-slate-200 bg-slate-50/60'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-900 text-sm">
                      {event.timestamp}
                    </span>
                    <span className="text-slate-300">•</span>
                    <span className="font-bold text-slate-800 text-sm">
                      {event.event}
                    </span>
                  </div>

                  <div className="font-mono text-[11px] text-slate-500 bg-white/80 px-2 py-0.5 rounded border border-slate-200 w-fit">
                    IP: {event.ip}
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-600 mb-1">
                  Node: {event.node}
                </div>

                <p className="text-slate-600 leading-relaxed font-normal">
                  {event.details}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
