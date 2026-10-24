import React, { useState } from 'react';
import { ThreatIntelligenceIndicator } from '../../types/forensics';
import { ThreatIntelTable } from '../investigation/ThreatIntelTable';
import { Database, Search, ShieldCheck, ExternalLink, RefreshCw, Plus, X } from 'lucide-react';
import { createIocRecord, fetchAllUserIocs, mapIocToThreatIntel } from '../../services/iocService';

interface ThreatIntelViewProps {
  indicators: ThreatIntelligenceIndicator[];
  onRefresh?: () => Promise<void>;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({ indicators, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('All');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isAddOpen, setIsAddOpen] = useState(false);

  // New IOC form state
  const [newType, setNewType] = useState<'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256'>('Domain');
  const [newValue, setNewValue] = useState('');
  const [newRisk, setNewRisk] = useState<'Clean' | 'Suspicious' | 'Malicious' | 'High' | 'Critical'>('Malicious');
  const [newDetails, setNewDetails] = useState('');
  const [savingIoc, setSavingIoc] = useState(false);

  const types = ['All', 'Domain', 'IP', 'URL', 'Attachment', 'SHA-256'];

  const filtered = indicators.filter((item) => {
    if (selectedType !== 'All' && item.type !== selectedType) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      return item.indicator.toLowerCase().includes(q) || item.details.toLowerCase().includes(q);
    }
    return true;
  });

  const handleRefresh = async () => {
    setIsRefreshing(true);
    if (onRefresh) {
      await onRefresh();
    } else {
      await new Promise((r) => setTimeout(r, 600));
    }
    setIsRefreshing(false);
  };

  const handleAddIocSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim()) return;

    setSavingIoc(true);
    try {
      await createIocRecord('CASE-1024', {
        indicator_type: newType,
        indicator_value: newValue.trim(),
        risk_level: newRisk,
        metadata: {
          details: newDetails || `Manually cataloged ${newType} threat`,
          source: 'Analyst Threat Intel Submission',
          confidence: 90,
          firstSeen: new Date().toISOString().split('T')[0]
        }
      });

      if (onRefresh) await onRefresh();
      setIsAddOpen(false);
      setNewValue('');
      setNewDetails('');
    } finally {
      setSavingIoc(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Threat Intelligence</h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Global telemetry correlation of active phishing kits, bulletproof hosting ASNs, and dropper signatures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsAddOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 shadow-sm transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Indicator</span>
          </button>

          <button
            onClick={handleRefresh}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 shadow-xs transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-blue-600' : ''}`} />
            <span>Sync Feed</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1.5">
          {types.map((t) => (
            <button
              key={t}
              onClick={() => setSelectedType(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                selectedType === t
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="relative min-w-[280px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search IOC, domain, hash, or IP..."
            className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100 transition-all"
          />
        </div>
      </div>

      <ThreatIntelTable indicators={filtered} />

      {/* Add IOC Modal */}
      {isAddOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
            <button
              onClick={() => setIsAddOpen(false)}
              className="absolute right-4 top-4 p-1.5 text-slate-400 hover:text-slate-700 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="mb-4">
              <h3 className="text-lg font-bold text-slate-900">Add Threat Indicator</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Record a malicious IP, domain, URL, or hash in the Supabase threat feed.
              </p>
            </div>

            <form onSubmit={handleAddIocSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Indicator Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 focus:bg-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="Domain">Domain</option>
                  <option value="IP">IP Address</option>
                  <option value="URL">URL</option>
                  <option value="SHA-256">SHA-256 Hash</option>
                  <option value="Attachment">Attachment</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Indicator Value</label>
                <input
                  type="text"
                  required
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  placeholder="e.g. evil-phishing-login.com or 185.220.101.42"
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 focus:bg-white focus:border-blue-500 focus:outline-none font-mono"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Reputation / Risk Level</label>
                <select
                  value={newRisk}
                  onChange={(e) => setNewRisk(e.target.value as any)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 focus:bg-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="Malicious">Malicious</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="Critical">Critical</option>
                  <option value="Clean">Clean</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Context / Telemetry Notes</label>
                <textarea
                  value={newDetails}
                  onChange={(e) => setNewDetails(e.target.value)}
                  placeholder="e.g. C2 drop site or credential harvester observed in active campaigns"
                  rows={2}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 p-2 text-slate-900 focus:bg-white focus:border-blue-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={savingIoc || !newValue.trim()}
                className="w-full rounded-xl bg-blue-600 py-2.5 text-xs font-bold text-white shadow-md hover:bg-blue-700 disabled:opacity-50 transition-all cursor-pointer"
              >
                {savingIoc ? 'Persisting to Database...' : 'Save Indicator to Database'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
