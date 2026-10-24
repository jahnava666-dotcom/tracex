import React, { useState, useEffect } from 'react';
import { User, Bell, Palette, Sliders, Check, Shield, Database, KeyRound, Loader2, RefreshCw } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { testSupabaseConnection } from '../../lib/supabase';

export const SettingsView: React.FC = () => {
  const { user, profile, updateProfileName, resetPassword } = useAuth();
  const [name, setName] = useState(profile?.full_name || 'Alex Carter');
  const [email, setEmail] = useState(user?.email || 'alex.carter@corporate-security.net');
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [darkMode, setDarkMode] = useState(false);
  const [autoReport, setAutoReport] = useState(true);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  // Connection test state
  const [testingConn, setTestingConn] = useState(false);
  const [connResult, setConnResult] = useState<{ connected: boolean; message: string } | null>(null);

  // Password reset state
  const [resettingPw, setResettingPw] = useState(false);
  const [pwResetMsg, setPwResetMsg] = useState<string | null>(null);

  useEffect(() => {
    if (profile?.full_name) setName(profile.full_name);
    if (user?.email) setEmail(user.email);
  }, [profile, user]);

  const handleSave = async () => {
    setSaving(true);
    if (user && name !== profile?.full_name) {
      await updateProfileName(name);
    }
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const handleTestConnection = async () => {
    setTestingConn(true);
    setConnResult(null);
    const res = await testSupabaseConnection();
    setConnResult(res);
    setTestingConn(false);
  };

  const handleTriggerPasswordReset = async () => {
    if (!email) return;
    setResettingPw(true);
    setPwResetMsg(null);
    const { error } = await resetPassword(email);
    setResettingPw(false);
    if (error) {
      setPwResetMsg(`Error: ${error.message}`);
    } else {
      setPwResetMsg('Password reset instructions dispatched to your email.');
    }
  };

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Settings & Infrastructure</h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Configure analyst credentials, notification thresholds, and Supabase database parameters.
          </p>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 shadow-sm transition-all cursor-pointer disabled:opacity-60"
        >
          {saving ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : saved ? (
            <Check className="w-3.5 h-3.5" />
          ) : null}
          <span>{saving ? 'Saving...' : saved ? 'Preferences Saved!' : 'Save Changes'}</span>
        </button>
      </div>

      {/* Supabase Integration Status Card */}
      <div className="rounded-2xl border border-blue-200 bg-blue-50/40 p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-blue-100 pb-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900">
            <Database className="w-4 h-4 text-blue-600" />
            <span>Supabase Cloud Integration</span>
          </div>

          <button
            onClick={handleTestConnection}
            disabled={testingConn}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-blue-200 text-blue-700 text-xs font-semibold hover:bg-blue-50 shadow-xs transition-all cursor-pointer disabled:opacity-60"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testingConn ? 'animate-spin' : ''}`} />
            <span>{testingConn ? 'Testing...' : 'Test Connection'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <span className="text-slate-500 font-semibold block mb-0.5">Project Endpoint URL:</span>
            <div className="font-mono text-slate-800 bg-white p-2 rounded-lg border border-blue-200 truncate select-all">
              {import.meta.env.VITE_SUPABASE_URL || 'https://cxmxlmijwaaptewtfczg.supabase.co'}
            </div>
          </div>

          <div>
            <span className="text-slate-500 font-semibold block mb-0.5">Publishable Client Key:</span>
            <div className="font-mono text-slate-800 bg-white p-2 rounded-lg border border-blue-200 truncate select-all">
              {import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY
                ? `${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY.substring(0, 16)}...`
                : 'sb_publishable_...'}
            </div>
          </div>
        </div>

        {connResult && (
          <div
            className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
              connResult.connected
                ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            <div className={`w-2 h-2 rounded-full ${connResult.connected ? 'bg-emerald-600' : 'bg-red-600'}`} />
            <span>{connResult.message}</span>
          </div>
        )}

        <div className="flex items-center gap-2 text-[11px] text-slate-500 font-mono">
          <Shield className="w-3.5 h-3.5 text-blue-600" />
          <span>RLS & Auth: Authenticated Row Level Security, Append-Only Audits & Private Evidence Storage</span>
        </div>
      </div>

      {/* Account Section */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900">
            <User className="w-4 h-4 text-blue-600" />
            <span>Analyst Profile</span>
          </div>

          <span className="text-[10px] font-mono bg-slate-100 text-slate-600 px-2 py-0.5 rounded uppercase font-semibold">
            Role: {profile?.role || 'Analyst'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block text-slate-600 font-semibold mb-1">Analyst Full Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100"
            />
          </div>
          <div>
            <label className="block text-slate-600 font-semibold mb-1">Corporate Email Address</label>
            <input
              type="email"
              disabled
              value={email}
              className="w-full rounded-xl border border-slate-200 bg-slate-100 px-3 py-2 text-slate-600 cursor-not-allowed"
            />
          </div>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-t border-slate-100">
          <div>
            <div className="font-semibold text-slate-800 text-xs">Security Credentials</div>
            <div className="text-[11px] text-slate-500">Need to update your Supabase password?</div>
          </div>

          <button
            type="button"
            onClick={handleTriggerPasswordReset}
            disabled={resettingPw}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 shadow-xs transition-all"
          >
            <KeyRound className="w-3.5 h-3.5 text-slate-500" />
            <span>{resettingPw ? 'Sending...' : 'Request Password Reset'}</span>
          </button>
        </div>

        {pwResetMsg && (
          <div className="p-3 rounded-xl bg-blue-50 border border-blue-200 text-blue-800 text-xs">
            {pwResetMsg}
          </div>
        )}
      </div>

      {/* Notifications Section */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-900 border-b border-slate-100 pb-3">
          <Bell className="w-4 h-4 text-amber-500" />
          <span>Notification Alerts</span>
        </div>

        <div className="space-y-3 text-xs">
          <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div>
              <div className="font-semibold text-slate-800">Email Alerts</div>
              <div className="text-slate-500 text-[11px]">Receive digest notifications when new email files are triaged.</div>
            </div>
            <button
              onClick={() => setEmailAlerts(!emailAlerts)}
              className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                emailAlerts ? 'bg-blue-600' : 'bg-slate-300'
              }`}
            >
              <div
                className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                  emailAlerts ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div>
              <div className="font-semibold text-slate-800">Critical Threat Alerts</div>
              <div className="text-slate-500 text-[11px]">Immediately page on-duty SOC analyst when risk score exceeds 80/100.</div>
            </div>
            <button
              onClick={() => setCriticalAlerts(!criticalAlerts)}
              className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                criticalAlerts ? 'bg-blue-600' : 'bg-slate-300'
              }`}
            >
              <div
                className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                  criticalAlerts ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Appearance Section */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-900 border-b border-slate-100 pb-3">
          <Palette className="w-4 h-4 text-indigo-500" />
          <span>Appearance</span>
        </div>

        <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100 text-xs">
          <div>
            <div className="font-semibold text-slate-800">Interface Theme</div>
            <div className="text-slate-500 text-[11px]">High-Contrast SOC Light theme (Optimized for forensic triage clarity).</div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-600 font-medium">Light</span>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                darkMode ? 'bg-blue-600' : 'bg-slate-300'
              }`}
            >
              <div
                className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                  darkMode ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
            <span className="text-xs text-slate-600 font-medium">Dark</span>
          </div>
        </div>
      </div>

      {/* Investigation Preferences */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-900 border-b border-slate-100 pb-3">
          <Sliders className="w-4 h-4 text-emerald-500" />
          <span>Forensic Engine Parameters</span>
        </div>

        <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100 text-xs">
          <div>
            <div className="font-semibold text-slate-800">Automatic Evidence & Hash Archiving</div>
            <div className="text-slate-500 text-[11px]">Automatically calculate SHA-256 and sync evidence to Supabase on upload.</div>
          </div>
          <button
            onClick={() => setAutoReport(!autoReport)}
            className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
              autoReport ? 'bg-blue-600' : 'bg-slate-300'
            }`}
          >
            <div
              className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                autoReport ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>
    </div>
  );
};
