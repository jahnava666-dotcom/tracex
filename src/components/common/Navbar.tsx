import React, { useState } from 'react';
import { Search, Bell, Shield, User, Menu, X, CheckCheck, ExternalLink, LogIn, LogOut, CheckCircle2, ChevronDown } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { AuthModal } from '../auth/AuthModal';

interface NavbarProps {
  onNavigateHome?: () => void;
  onOpenMobileMenu?: () => void;
  isMobileMenuOpen?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  onNavigateHome,
  onOpenMobileMenu,
  isMobileMenuOpen
}) => {
  const { user, profile, signOut, isConfigured } = useAuth();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const notifications = [
    {
      id: 1,
      title: 'Critical Threat Alert: CASE-1024',
      desc: 'Credential harvester & ZIP dropper detected from 185.220.101.42',
      time: '12m ago',
      unread: true,
      urgent: true
    },
    {
      id: 2,
      title: 'DMARC Policy Enforcement',
      desc: '3 automated quarantines applied to suspicious sender envelopes',
      time: '1h ago',
      unread: true,
      urgent: false
    },
    {
      id: 3,
      title: 'Supabase Realtime Synced',
      desc: 'Connected to live Supabase postgres replication cluster',
      time: 'Just now',
      unread: false,
      urgent: false
    }
  ];

  const getInitials = () => {
    if (profile?.full_name) {
      return profile.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .substring(0, 2);
    }
    if (user?.email) {
      return user.email.substring(0, 2).toUpperCase();
    }
    return 'AC';
  };

  const displayName = profile?.full_name || user?.email?.split('@')[0] || 'Alex Carter';
  const displayRole = profile?.role ? `${profile.role.replace('_', ' ').toUpperCase()}` : 'SOC Analyst (Demo)';

  return (
    <>
      <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-200 bg-white/95 px-4 sm:px-6 backdrop-blur-md">
        <div className="flex items-center gap-3">
          {/* Mobile hamburger */}
          <button
            onClick={onOpenMobileMenu}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-800 lg:hidden focus:outline-none"
            aria-label="Toggle navigation menu"
          >
            {isMobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>

          {/* Logo */}
          <div
            onClick={onNavigateHome}
            className="flex cursor-pointer items-center gap-2.5 transition-opacity hover:opacity-90"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 shadow-sm shadow-blue-500/20 text-white">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="text-lg font-bold tracking-tight text-slate-900">TRACE-X</span>
                <span className="rounded bg-blue-100 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-blue-700">
                  AI + Supabase
                </span>
              </div>
              <span className="hidden text-[10px] font-medium text-slate-500 sm:inline-block">
                Detect. Trace. Investigate.
              </span>
            </div>
          </div>
        </div>

        {/* Center Search */}
        <div className="hidden md:flex flex-1 max-w-md mx-6">
          <div className="relative w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search Case ID, IP, Domain, Hash, or Evidence..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-9 pr-3 text-sm text-slate-800 placeholder-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all"
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] bg-slate-200 text-slate-600 rounded px-1.5 py-0.5 font-mono">
              ⌘K
            </span>
          </div>
        </div>

        {/* Right User & Notification Controls */}
        <div className="flex items-center gap-3">
          {/* Status indicator */}
          <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-medium">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>{user ? 'Supabase RLS Active' : 'Supabase Connected'}</span>
          </div>

          {/* Notification bell */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-800 transition-colors"
              aria-label="View security notifications"
            >
              <Bell className="h-5 w-5" />
              <span className="absolute right-1.5 top-1.5 flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500"></span>
              </span>
            </button>

            {/* Notifications Dropdown */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl border border-slate-200 bg-white p-2 shadow-xl shadow-slate-200/50 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                <div className="flex items-center justify-between px-3 py-2 border-b border-slate-100">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-slate-800">Security Alerts</span>
                    <span className="rounded-full bg-red-100 text-red-700 text-[10px] font-bold px-2 py-0.5">2 New</span>
                  </div>
                  <button
                    onClick={() => setShowNotifications(false)}
                    className="text-xs text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1"
                  >
                    <CheckCheck className="w-3.5 h-3.5" /> Mark read
                  </button>
                </div>

                <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
                  {notifications.map((n) => (
                    <div
                      key={n.id}
                      className={`p-3 hover:bg-slate-50 transition-colors rounded-lg cursor-pointer ${
                        n.unread ? 'bg-blue-50/40' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className={`text-xs font-semibold ${n.urgent ? 'text-red-700' : 'text-slate-800'}`}>
                          {n.title}
                        </span>
                        <span className="text-[10px] text-slate-400 whitespace-nowrap">{n.time}</span>
                      </div>
                      <p className="text-xs text-slate-600 mt-1 line-clamp-2">{n.desc}</p>
                    </div>
                  ))}
                </div>

                <div className="p-2 border-t border-slate-100 text-center">
                  <button
                    onClick={() => setShowNotifications(false)}
                    className="text-xs text-slate-500 hover:text-slate-800 font-medium inline-flex items-center gap-1"
                  >
                    View full security log <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* User Profile / Auth State */}
          {user ? (
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2.5 pl-2 border-l border-slate-200 hover:opacity-85 transition-opacity"
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-600 text-white font-bold text-xs ring-2 ring-blue-100">
                  {getInitials()}
                </div>
                <div className="hidden md:flex flex-col text-left">
                  <span className="text-xs font-semibold text-slate-800 leading-tight">{displayName}</span>
                  <span className="text-[10px] text-slate-500 font-medium">{displayRole}</span>
                </div>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400 hidden sm:block" />
              </button>

              {/* User Dropdown */}
              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl border border-slate-200 bg-white p-2 shadow-xl shadow-slate-200/50 z-50 animate-in fade-in duration-150">
                  <div className="px-3 py-2 border-b border-slate-100">
                    <div className="font-semibold text-xs text-slate-900 truncate">{displayName}</div>
                    <div className="text-[11px] text-slate-500 truncate">{user.email}</div>
                    <div className="mt-1 flex items-center gap-1 text-[10px] font-mono text-emerald-600">
                      <CheckCircle2 className="w-3 h-3" /> Authenticated via Supabase
                    </div>
                  </div>

                  <div className="py-1 text-xs">
                    <button
                      onClick={async () => {
                        setShowUserMenu(false);
                        await signOut();
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors text-left"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-2 pl-2 border-l border-slate-200">
              <button
                onClick={() => setIsAuthModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 shadow-sm transition-all"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Auth Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </>
  );
};
