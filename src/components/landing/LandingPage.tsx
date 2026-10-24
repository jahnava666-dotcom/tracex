import React from 'react';
import {
  Shield,
  ArrowRight,
  Play,
  Cpu,
  Lock,
  Globe2,
  Clock,
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  ChevronRight
} from 'lucide-react';

interface LandingPageProps {
  onGetStarted: () => void;
  onViewDemo: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onGetStarted, onViewDemo }) => {
  const features = [
    {
      icon: Cpu,
      title: 'AI Threat Detection',
      description: 'Identify suspicious email behavior using AI, rules and threat intelligence.',
      color: 'text-blue-600 bg-blue-50 border-blue-100',
    },
    {
      icon: Lock,
      title: 'Email Authentication',
      description: 'Analyze SPF, DKIM and DMARC alignment to uncover spoofing and forged envelope headers.',
      color: 'text-indigo-600 bg-indigo-50 border-indigo-100',
    },
    {
      icon: Globe2,
      title: 'Infrastructure Intelligence',
      description: 'Visualize IP, ASN, ISP and approximate infrastructure location across every server hop.',
      color: 'text-emerald-600 bg-emerald-50 border-emerald-100',
    },
    {
      icon: Clock,
      title: 'Forensic Timeline',
      description: 'Understand how the email moved through different servers with precise transit timestamps.',
      color: 'text-amber-600 bg-amber-50 border-amber-100',
    },
    {
      icon: FileCheck,
      title: 'Automated Report',
      description: 'Generate an investigation summary with IOCs and recommended actions ready for incident response.',
      color: 'text-slate-800 bg-slate-100 border-slate-200',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col justify-between selection:bg-blue-600 selection:text-white">
      {/* Top Banner & Header */}
      <header className="border-b border-slate-200/80 bg-white/80 backdrop-blur-md sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm shadow-blue-500/20">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xl font-black text-slate-900 tracking-tight">TRACE-X</span>
              <span className="text-xs font-bold text-blue-600 uppercase bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">
                Forensics
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onViewDemo}
              className="text-xs sm:text-sm font-semibold text-slate-600 hover:text-slate-900 px-3 py-2 transition-colors"
            >
              Demo Case (CASE-1024)
            </button>
            <button
              onClick={onGetStarted}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs sm:text-sm font-semibold text-white shadow-sm shadow-blue-600/30 hover:bg-blue-700 transition-all"
            >
              Get Started <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 pb-16">
        <div className="text-center max-w-3xl mx-auto">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-semibold mb-6">
            <span className="h-2 w-2 rounded-full bg-blue-600 animate-pulse"></span>
            Next-Gen Cybersecurity Email Forensics
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-900 leading-tight">
            Investigate suspicious emails with <span className="text-blue-600">AI-powered forensic intelligence.</span>
          </h1>

          <p className="mt-5 text-base sm:text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed">
            Analyze email headers, authentication, URLs, attachments, infrastructure and threat indicators in one place.
          </p>

          <p className="mt-2 text-xs font-mono font-medium text-slate-400">
            Turn suspicious emails into evidence-backed investigations.
          </p>

          {/* Action Buttons */}
          <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3.5">
            <button
              onClick={onGetStarted}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-600/25 hover:bg-blue-700 transition-all hover:scale-[1.01]"
            >
              <span>Get Started</span>
              <ArrowRight className="h-4 w-4" />
            </button>
            <button
              onClick={onViewDemo}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-6 py-3.5 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50 hover:border-slate-300 transition-all"
            >
              <Play className="h-4 w-4 text-blue-600 fill-blue-600" />
              <span>View Demo</span>
            </button>
          </div>
        </div>

        {/* Live Forensic Preview Card / Teaser */}
        <div className="mt-14 max-w-4xl mx-auto rounded-2xl border border-slate-200 bg-white p-5 shadow-xl shadow-slate-200/40">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3.5">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-red-500"></span>
              <span className="h-3 w-3 rounded-full bg-amber-500"></span>
              <span className="h-3 w-3 rounded-full bg-emerald-500"></span>
              <span className="ml-2 text-xs font-mono font-semibold text-slate-600">CASE-1024 / Triage Telemetry</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-red-100 text-red-700 text-xs font-bold px-2.5 py-0.5 border border-red-200">
                CRITICAL THREAT (92/100)
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 text-left">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-100">
              <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">Auth Status</div>
              <div className="mt-2 space-y-1 text-xs">
                <div className="flex justify-between"><span>SPF:</span> <span className="font-semibold text-red-600">FAIL (Unpermitted IP)</span></div>
                <div className="flex justify-between"><span>DKIM:</span> <span className="font-semibold text-amber-600">SUSPICIOUS (Hash mismatch)</span></div>
                <div className="flex justify-between"><span>DMARC:</span> <span className="font-semibold text-red-600">FAIL (Strict Reject)</span></div>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-100">
              <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">Primary Infrastructure</div>
              <div className="mt-2 space-y-1 text-xs text-slate-700">
                <div className="font-mono text-slate-900 font-semibold">185.220.101.42</div>
                <div>AS49453 (Global Host Solutions)</div>
                <div className="text-slate-500">Amsterdam, Netherlands (VPS Relay)</div>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-100">
              <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">Detected Payload</div>
              <div className="mt-2 space-y-1 text-xs text-slate-700">
                <div className="font-medium text-slate-900 flex items-center gap-1">
                  <span className="text-red-600 font-bold">⚠️</span> Invoice_2026.zip
                </div>
                <div className="text-slate-500">Obfuscated VBScript Dropper</div>
                <div className="text-[11px] text-blue-600 font-mono">2 URLs Extracted & Correlated</div>
              </div>
            </div>
          </div>
        </div>

        {/* Feature Cards Grid */}
        <section className="mt-20">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <h2 className="text-xs uppercase tracking-widest font-bold text-blue-600">Platform Capabilities</h2>
            <p className="mt-1 text-2xl font-bold text-slate-900">Engineered for Rapid Cyber Incident Response</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 text-left">
            {features.map((f, i) => {
              const Icon = f.icon;
              return (
                <div
                  key={i}
                  className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm hover:shadow-md transition-shadow"
                >
                  <div className={`inline-flex p-3 rounded-xl border ${f.color} mb-4`}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-900">{f.title}</h3>
                  <p className="mt-2 text-xs sm:text-sm text-slate-600 leading-relaxed">
                    {f.description}
                  </p>
                </div>
              );
            })}

            {/* Call to action mini-card */}
            <div
              onClick={onGetStarted}
              className="cursor-pointer rounded-2xl border border-dashed border-blue-300 bg-blue-50/50 p-6 flex flex-col justify-between hover:bg-blue-50 transition-colors group"
            >
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-blue-600">Interactive Demo</span>
                <h3 className="text-base font-bold text-slate-900 mt-1">Ready to test a suspicious email?</h3>
                <p className="text-xs text-slate-600 mt-2">
                  Launch the interactive forensic sandbox with sample telemetry.
                </p>
              </div>
              <div className="mt-4 flex items-center gap-1.5 text-xs font-bold text-blue-600 group-hover:translate-x-1 transition-transform">
                Launch Workspace <ChevronRight className="h-4 w-4" />
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row items-center gap-2">
            <span className="font-bold text-slate-800">TRACE-X</span>
            <span className="hidden sm:inline">—</span>
            <span className="text-slate-600">AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform</span>
            <span className="hidden md:inline font-medium text-blue-600">Detect. Trace. Investigate.</span>
          </div>
          <div>Forensic Prototype & Demonstration Platform</div>
        </div>
      </footer>
    </div>
  );
};
