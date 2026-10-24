import React, { useState, useEffect, useCallback, useRef } from 'react';
import { NavigationTab, Sidebar } from './components/common/Sidebar';
import { Navbar } from './components/common/Navbar';
import { LandingPage } from './components/landing/LandingPage';
import { DashboardView } from './components/dashboard/DashboardView';
import { DropZone } from './components/analyze/DropZone';
import { AnalysisProgress } from './components/analyze/AnalysisProgress';
import { InvestigationResultsView } from './components/investigation/InvestigationResultsView';
import { InvestigationsView } from './components/pages/InvestigationsView';
import { EvidenceVaultView } from './components/pages/EvidenceVaultView';
import { ThreatIntelView } from './components/pages/ThreatIntelView';
import { ReportsView } from './components/pages/ReportsView';
import { SettingsView } from './components/pages/SettingsView';
import { CASE_1024, RECENT_INVESTIGATIONS, MOCK_REPORTS } from './data/mockData';
import { EmailInvestigationCase } from './types/forensics';
import { apiClient } from './api/client';
import { useAuth } from './context/AuthContext';
import { fetchDashboardStats, DashboardStats } from './services/statsService';
import { updateInvestigationStatusInDb, deleteInvestigationFromDb } from './services/investigationService';
import { useSupabaseRealtime } from './hooks/useSupabaseRealtime';
import { TraceXAssistant } from './components/chat/TraceXAssistant';

export const App: React.FC = () => {
  const { user } = useAuth();

  // App views: 'landing' or in-app tabs
  const [currentView, setCurrentView] = useState<
    | 'landing'
    | 'dashboard'
    | 'analyze'
    | 'analyzing'
    | 'results'
    | 'investigations'
    | 'evidence'
    | 'threat-intel'
    | 'reports'
    | 'settings'
  >('landing');

  const [activeCase, setActiveCase] = useState<EmailInvestigationCase>(CASE_1024);
  const [casesList, setCasesList] = useState<EmailInvestigationCase[]>(RECENT_INVESTIGATIONS);
  const [isDemoFallback, setIsDemoFallback] = useState(true);
  const [dashboardStats, setDashboardStats] = useState<DashboardStats | undefined>(undefined);
  const [reportsList, setReportsList] = useState(MOCK_REPORTS);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Stored analysis result while animation runs
  const pendingAnalysisRef = useRef<EmailInvestigationCase | null>(null);

  // Load investigations & dashboard stats from Supabase
  const loadData = useCallback(async () => {
    try {
      const { cases, isDemo } = await apiClient.getInvestigations();
      setCasesList(cases);
      setIsDemoFallback(isDemo);

      const stats = await fetchDashboardStats();
      setDashboardStats(stats);

      const reports = await apiClient.getReports();
      if (reports && reports.length > 0) {
        setReportsList(reports);
      }
    } catch (err) {
      console.warn('[TRACE-X] Error loading initial data:', err);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [user, loadData]);

  // Real-time Supabase listeners
  useSupabaseRealtime({
    table: 'investigations',
    onInsert: () => {
      loadData();
    },
    onUpdate: () => {
      loadData();
    },
    onDelete: () => {
      loadData();
    },
    enabled: Boolean(user)
  });

  useSupabaseRealtime({
    table: 'email_analyses',
    onInsert: () => {
      loadData();
    },
    enabled: Boolean(user)
  });

  // Active sidebar navigation mapping
  const getSidebarTab = (): NavigationTab => {
    if (currentView === 'dashboard') return 'dashboard';
    if (currentView === 'analyze' || currentView === 'analyzing') return 'analyze';
    if (currentView === 'investigations' || currentView === 'results') return 'investigations';
    if (currentView === 'evidence') return 'evidence';
    if (currentView === 'threat-intel') return 'threat-intel';
    if (currentView === 'reports') return 'reports';
    if (currentView === 'settings') return 'settings';
    return 'dashboard';
  };

  // 1. Landing Page Navigation
  const handleGetStarted = () => {
    setCurrentView('dashboard');
  };

  const handleViewDemo = () => {
    setActiveCase({ ...CASE_1024, isSimulatedDemo: true });
    setCurrentView('results');
  };

  // 2. Analyze Email Flow
  const handleStartAnalysis = async (file?: File, rawText?: string) => {
    setCurrentView('analyzing');
    try {
      const result = await apiClient.analyzeEmail({ file, rawText, isDemo: false });
      pendingAnalysisRef.current = result;
    } catch {
      pendingAnalysisRef.current = { ...CASE_1024, isSimulatedDemo: false };
    }
  };

  const handleUseDemoEmail = () => {
    pendingAnalysisRef.current = { ...CASE_1024, isSimulatedDemo: true };
    setCurrentView('analyzing');
  };

  const handleAnalysisAnimationComplete = () => {
    if (pendingAnalysisRef.current) {
      const newlyAnalyzed = pendingAnalysisRef.current;
      setActiveCase(newlyAnalyzed);
      setCasesList((prev) => {
        const exists = prev.some((c) => c.caseId === newlyAnalyzed.caseId);
        return exists ? prev : [newlyAnalyzed, ...prev];
      });
      pendingAnalysisRef.current = null;
    }
    setCurrentView('results');
  };

  // 3. View Case Detail
  const handleViewCase = (caseItem: EmailInvestigationCase) => {
    setActiveCase(caseItem);
    setCurrentView('results');
  };

  // 4. Case Management CRUD
  const handleDeleteCase = async (caseId: string) => {
    await deleteInvestigationFromDb(caseId);
    setCasesList((prev) => prev.filter((c) => c.caseId !== caseId));
    loadData();
  };

  const handleUpdateStatus = async (
    caseId: string,
    newStatus: 'Open' | 'Under Review' | 'Mitigated' | 'Closed'
  ) => {
    await updateInvestigationStatusInDb(caseId, newStatus);
    setCasesList((prev) =>
      prev.map((c) => (c.caseId === caseId ? { ...c, status: newStatus } : c))
    );
  };

  // 5. Sidebar Nav Selection
  const handleSelectSidebarTab = (tab: NavigationTab) => {
    if (tab === 'analyze') {
      setCurrentView('analyze');
    } else if (tab === 'investigations') {
      setCurrentView('investigations');
    } else if (tab === 'evidence') {
      setCurrentView('evidence');
    } else if (tab === 'threat-intel') {
      setCurrentView('threat-intel');
    } else if (tab === 'reports') {
      setCurrentView('reports');
    } else if (tab === 'settings') {
      setCurrentView('settings');
    } else {
      setCurrentView('dashboard');
    }
  };

  const handleNavigateFromChat = (tab: NavigationTab | 'results') => {
    if (tab === 'results') {
      setCurrentView('results');
    } else {
      handleSelectSidebarTab(tab);
    }
  };

  // Render Landing Page
  if (currentView === 'landing') {
    return (
      <>
        <LandingPage
          onGetStarted={handleGetStarted}
          onViewDemo={handleViewDemo}
        />
        <TraceXAssistant
          currentView="landing"
          activeCase={activeCase}
          onNavigateTab={handleNavigateFromChat}
        />
      </>
    );
  }

  // Render Main Application Shell
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col selection:bg-blue-600 selection:text-white">
      {/* Top Bar */}
      <Navbar
        onNavigateHome={() => setCurrentView('landing')}
        onOpenMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        isMobileMenuOpen={isMobileMenuOpen}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          activeTab={getSidebarTab()}
          onSelectTab={handleSelectSidebarTab}
          isMobileOpen={isMobileMenuOpen}
          onCloseMobile={() => setIsMobileMenuOpen(false)}
        />

        {/* Main Content Workspace Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <div className="max-w-7xl mx-auto">
            {currentView === 'dashboard' && (
              <DashboardView
                cases={casesList}
                onViewCase={handleViewCase}
                onNavigateToAnalyze={() => setCurrentView('analyze')}
                stats={dashboardStats}
                isDemoFallback={isDemoFallback}
              />
            )}

            {currentView === 'analyze' && (
              <DropZone
                onStartAnalysis={handleStartAnalysis}
                onUseDemo={handleUseDemoEmail}
              />
            )}

            {currentView === 'analyzing' && (
              <AnalysisProgress
                onComplete={handleAnalysisAnimationComplete}
              />
            )}

            {currentView === 'results' && (
              <InvestigationResultsView
                caseData={activeCase}
                onBackToDashboard={() => setCurrentView('dashboard')}
              />
            )}

            {currentView === 'investigations' && (
              <InvestigationsView
                cases={casesList}
                onViewCase={handleViewCase}
                onDeleteCase={handleDeleteCase}
                onUpdateStatus={handleUpdateStatus}
              />
            )}

            {currentView === 'evidence' && (
              <EvidenceVaultView
                caseIdFilter={activeCase?.caseId}
              />
            )}

            {currentView === 'threat-intel' && (
              <ThreatIntelView
                indicators={activeCase.threatIntel}
                onRefresh={loadData}
              />
            )}

            {currentView === 'reports' && (
              <ReportsView
                reports={reportsList}
                cases={casesList}
              />
            )}

            {currentView === 'settings' && (
              <SettingsView />
            )}
          </div>
        </main>
      </div>

      {/* Floating TRACE-X Assistant AI Chatbot */}
      <TraceXAssistant
        currentView={currentView}
        activeCase={activeCase}
        onNavigateTab={handleNavigateFromChat}
      />
    </div>
  );
};

export default App;
