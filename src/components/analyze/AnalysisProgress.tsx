import React, { useState, useEffect } from 'react';
import { Shield, Check, Loader2, FastForward } from 'lucide-react';

interface AnalysisProgressProps {
  onComplete: () => void;
}

export const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ onComplete }) => {
  const steps = [
    'Email parsed',
    'Header information extracted',
    'SPF/DKIM/DMARC checked',
    'URLs analyzed',
    'Attachments analyzed',
    'IP infrastructure identified',
    'Threat intelligence correlated',
    'Generating forensic assessment...'
  ];

  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    // Progress through steps at ~350ms per step
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev < steps.length - 1) {
          return prev + 1;
        } else {
          clearInterval(interval);
          setTimeout(() => {
            onComplete();
          }, 450);
          return prev;
        }
      });
    }, 320);

    return () => clearInterval(interval);
  }, [steps.length, onComplete]);

  return (
    <div className="max-w-xl mx-auto py-12 px-4">
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-xl shadow-slate-200/50 text-center">
        {/* Animated Scanner Shield */}
        <div className="relative mx-auto mb-6 flex h-20 w-20 items-center justify-center">
          <div className="absolute inset-0 rounded-full border-4 border-blue-100 border-t-blue-600 animate-spin"></div>
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-blue-50 text-blue-600">
            <Shield className="h-7 w-7" />
          </div>
        </div>

        <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
          Analyzing Email
        </h2>
        <p className="text-xs sm:text-sm text-slate-500 mt-1">
          Executing multi-stage forensic heuristics and sandbox analysis...
        </p>

        {/* Steps List */}
        <div className="mt-8 space-y-2.5 text-left max-w-md mx-auto">
          {steps.map((step, idx) => {
            const isFinished = idx < currentStepIndex;
            const isCurrent = idx === currentStepIndex;
            const isPending = idx > currentStepIndex;

            return (
              <div
                key={idx}
                className={`flex items-center justify-between rounded-lg px-3 py-2 text-xs font-mono transition-all duration-200 ${
                  isFinished
                    ? 'bg-emerald-50 text-emerald-800 font-medium'
                    : isCurrent
                    ? 'bg-blue-50 text-blue-800 font-bold ring-1 ring-blue-200 shadow-sm'
                    : 'text-slate-400 opacity-60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  {isFinished ? (
                    <span className="flex h-4 w-4 items-center justify-center rounded-full bg-emerald-600 text-white">
                      <Check className="h-3 w-3 stroke-[3]" />
                    </span>
                  ) : isCurrent ? (
                    <span className="flex h-4 w-4 items-center justify-center">
                      <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
                    </span>
                  ) : (
                    <span className="h-4 w-4 rounded-full border border-slate-300 flex items-center justify-center text-[10px] text-slate-400">
                      ○
                    </span>
                  )}
                  <span>{step}</span>
                </div>

                {isFinished && (
                  <span className="text-[10px] uppercase tracking-wider text-emerald-600 font-semibold">Done</span>
                )}
                {isCurrent && (
                  <span className="text-[10px] uppercase tracking-wider text-blue-600 font-semibold animate-pulse">Running</span>
                )}
              </div>
            );
          })}
        </div>

        {/* Skip Animation button for presentations */}
        <div className="mt-8 pt-4 border-t border-slate-100 flex justify-center">
          <button
            onClick={onComplete}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-700 transition-colors"
          >
            <FastForward className="w-3.5 h-3.5" />
            <span>Skip animation</span>
          </button>
        </div>
      </div>
    </div>
  );
};
