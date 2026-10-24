import React from 'react';
import {
  LayoutDashboard,
  MailSearch,
  ShieldAlert,
  Database,
  FileText,
  Settings,
  HelpCircle,
  ExternalLink,
  ChevronRight,
  FolderLock
} from 'lucide-react';

export type NavigationTab =
  | 'dashboard'
  | 'analyze'
  | 'investigations'
  | 'evidence'
  | 'threat-intel'
  | 'reports'
  | 'settings';

interface SidebarProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  isMobileOpen,
  onCloseMobile
}) => {
  const navItems = [
    {
      id: 'dashboard' as NavigationTab,
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
      description: 'System overview & metrics'
    },
    {
      id: 'analyze' as NavigationTab,
      label: 'Analyze Email',
      icon: MailSearch,
      badge: 'Core',
      badgeColor: 'bg-blue-100 text-blue-700',
      description: 'Upload & forensic parser'
    },
    {
      id: 'investigations' as NavigationTab,
      label: 'Investigations',
      icon: ShieldAlert,
      badge: '4 Active',
      badgeColor: 'bg-amber-100 text-amber-800',
      description: 'Historical case records'
    },
    {
      id: 'evidence' as NavigationTab,
      label: 'Evidence Vault',
      icon: FolderLock,
      badge: 'SHA-256',
      badgeColor: 'bg-emerald-100 text-emerald-800',
      description: 'Digital evidence & custody'
    },
    {
      id: 'threat-intel' as NavigationTab,
      label: 'Threat Intelligence',
      icon: Database,
      badge: null,
      description: 'Domain, IP & hash feed'
    },
    {
      id: 'reports' as NavigationTab,
      label: 'Reports',
      icon: FileText,
      badge: null,
      description: 'Exported audit dossiers'
    },
    {
      id: 'settings' as NavigationTab,
      label: 'Settings',
      icon: Settings,
      badge: null,
      description: 'Engine & user preferences'
    }
  ];

  const handleNavClick = (tab: NavigationTab) => {
    onSelectTab(tab);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile backdrop */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-slate-900/40 backdrop-blur-sm lg:hidden"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-16 bottom-0 left-0 z-40 w-64 border-r border-slate-200 bg-white transition-transform duration-200 ease-in-out lg:static lg:translate-x-0 ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full'
        } flex flex-col justify-between`}
      >
        <div className="p-4 space-y-6">
          <div className="space-y-1">
            <div className="px-3 pb-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Investigation Suite
            </div>
            <nav className="space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleNavClick(item.id)}
                    className={`group flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 font-semibold shadow-sm shadow-blue-500/5'
                        : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Icon
                        className={`h-4 w-4 transition-colors ${
                          isActive ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-600'
                        }`}
                      />
                      <span>{item.label}</span>
                    </div>

                    {item.badge && (
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                          item.badgeColor || 'bg-slate-100 text-slate-600'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Forensic Quick Tip Box */}
          <div className="rounded-xl border border-blue-100 bg-gradient-to-b from-blue-50/60 to-slate-50/80 p-3.5 text-left">
            <div className="flex items-center gap-2 text-xs font-semibold text-blue-900">
              <span className="flex h-2 w-2 rounded-full bg-blue-600"></span>
              Forensic Tip
            </div>
            <p className="mt-1.5 text-xs text-slate-600 leading-relaxed">
              Always verify <strong>DMARC alignment</strong> against the RFC 5322 From address rather than Return-Path.
            </p>
          </div>
        </div>

        {/* Bottom Platform Info */}
        <div className="border-t border-slate-100 p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span className="font-mono text-[11px]">TRACE-X Core v2.4</span>
            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-600 font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span> Online
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>SOC Workstation</span>
            <span className="font-mono">US-EAST-01</span>
          </div>
        </div>
      </aside>
    </>
  );
};
