import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  MessageSquare,
  X,
  Send,
  Sparkles,
  Bot,
  User,
  Copy,
  Check,
  RotateCcw,
  Trash2,
  Maximize2,
  Minimize2,
  ChevronRight,
  Shield,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  Cpu,
  HelpCircle,
  FileSearch,
  Lock,
  Compass
} from 'lucide-react';
import { apiClient, ChatMessageResponse, ChatActionItem } from '../../api/client';
import { EmailInvestigationCase } from '../../types/forensics';
import { NavigationTab } from '../common/Sidebar';

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  mode?: 'ai_llm' | 'rule_based_expert' | 'fallback_error';
  intent?: string;
  topic?: string;
  confidence?: number;
  provider?: string;
  actions?: ChatActionItem[];
  suggestedQuestions?: string[];
  disclaimer?: string;
  failed?: boolean;
}

interface TraceXAssistantProps {
  currentView: string;
  activeCase?: EmailInvestigationCase;
  onNavigateTab: (tab: NavigationTab | 'results') => void;
}

const INITIAL_WELCOME_MESSAGE: ChatMessage = {
  id: 'welcome-msg',
  sender: 'assistant',
  text: `### Welcome to TRACE-X Assistant\n\nI am your **AI-Powered Forensic Intelligence Copilot** for email threat analysis, infrastructure tracking, and digital evidence verification.\n\n**How can I assist your investigation?**\n- Analyze email headers (SPF, DKIM, DMARC alignment, Return-Path, Received hops)\n- Evaluate suspicious emails for phishing, BEC, and dropper attachments\n- Interpret IP geolocation, BGP routing hops, and infrastructure attribution\n- Guide digital evidence acquisition, SHA-256 verification, and chain-of-custody\n- Help navigate TRACE-X investigations, cases, and forensic report generation`,
  timestamp: 'Just now',
  mode: 'rule_based_expert',
  intent: 'app_usage',
  provider: 'TRACE-X Forensic Intelligence Core',
  suggestedQuestions: [
    'How do I analyze an email?',
    'Is this email suspicious?',
    'What do SPF, DKIM, and DMARC mean?',
    'How accurate is IP geolocation?',
    'How do I verify evidence integrity?'
  ],
  actions: [
    { label: 'Analyze an Email', action: 'navigate_analyze' },
    { label: 'Open Dashboard', action: 'navigate_dashboard' }
  ]
};

export const TraceXAssistant: React.FC<TraceXAssistantProps> = ({
  currentView,
  activeCase,
  onNavigateTab
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_WELCOME_MESSAGE]);
  const [inputValue, setInputValue] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [sessionId] = useState(() => `sess-${Date.now()}-${Math.floor(Math.random() * 1000)}`);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen, scrollToBottom]);

  // Focus textarea when chat opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        textareaRef.current?.focus();
      }, 150);
    }
  }, [isOpen]);

  // Copy response handler
  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedMessageId(id);
    setTimeout(() => setCopiedMessageId(null), 2000);
  };

  // Clear conversation handler
  const handleClearChat = async () => {
    await apiClient.clearChatHistory(sessionId);
    setMessages([INITIAL_WELCOME_MESSAGE]);
    setShowClearConfirm(false);
  };

  // Execute interactive chatbot action
  const handleActionClick = (action: string) => {
    if (action === 'navigate_analyze') {
      onNavigateTab('analyze');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_dashboard') {
      onNavigateTab('dashboard');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_cases') {
      onNavigateTab('investigations');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_evidence') {
      onNavigateTab('evidence');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_reports') {
      onNavigateTab('reports');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_results' || action === 'explain_risk_score') {
      onNavigateTab('results');
      if (window.innerWidth < 768) setIsOpen(false);
    } else if (action === 'navigate_threat_intel') {
      onNavigateTab('threat-intel');
      if (window.innerWidth < 768) setIsOpen(false);
    }
  };

  // Send message
  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputValue).trim();
    if (!query || isProcessing) return;

    const userMessage: ChatMessage = {
      id: `usr-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMessage]);
    if (!textToSend) setInputValue('');
    setIsProcessing(true);

    try {
      const response: ChatMessageResponse = await apiClient.sendChatMessage(
        query,
        sessionId,
        {
          current_page: currentView,
          case_id: activeCase?.caseId,
          case_data: activeCase
        }
      );

      const assistantMessage: ChatMessage = {
        id: `asst-${Date.now()}`,
        sender: 'assistant',
        text: response.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        mode: response.mode,
        intent: response.intent,
        topic: response.topic,
        confidence: response.confidence,
        provider: response.provider,
        actions: response.actions,
        suggestedQuestions: response.suggested_questions,
        disclaimer: response.disclaimer
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        sender: 'assistant',
        text: 'I encountered an issue communicating with the TRACE-X intelligence service. Please click retry below or try rephrasing your question.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        failed: true,
        mode: 'fallback_error'
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRetryLast = () => {
    const lastUserMsg = [...messages].reverse().find((m) => m.sender === 'user');
    if (lastUserMsg) {
      handleSendMessage(lastUserMsg.text);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Quick categories for prompt chips
  const quickCategories = [
    { label: 'Phishing Check', query: 'Is this email suspicious?' },
    { label: 'SPF / DKIM / DMARC', query: 'What do SPF, DKIM, and DMARC mean?' },
    { label: 'Received Hops', query: 'How do Received headers help trace email routing?' },
    { label: 'IP Reliability', query: 'How reliable is an IP-based location estimate?' },
    { label: 'SHA-256 Hashing', query: 'What is a SHA-256 hash in email forensics?' },
    { label: 'Analyze Email', query: 'How do I analyze an email in TRACE-X?' }
  ];

  return (
    <>
      {/* Floating Trigger Button */}
      {!isOpen && (
        <div className="fixed bottom-6 right-6 z-40 flex items-center gap-3">
          {/* Subtle CTA badge visible on larger screens */}
          <div className="hidden sm:flex items-center gap-2 rounded-full border border-blue-200/90 bg-white/95 px-3.5 py-1.5 shadow-lg shadow-blue-500/10 backdrop-blur-md">
            <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-semibold text-slate-700">TRACE-X Assistant</span>
            <span className="rounded bg-blue-100 px-1.5 py-0.2 text-[10px] font-bold text-blue-700">Copilot</span>
          </div>

          <button
            onClick={() => setIsOpen(true)}
            className="group relative flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-tr from-blue-700 via-blue-600 to-indigo-600 text-white shadow-xl shadow-blue-600/30 transition-all hover:scale-105 hover:shadow-2xl hover:shadow-blue-600/40 focus:outline-none focus:ring-4 focus:ring-blue-300"
            aria-label="Open TRACE-X Assistant AI Chatbot"
          >
            <div className="absolute inset-0 rounded-2xl bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            <Bot className="h-6 w-6 transition-transform group-hover:scale-110" />
            <span className="absolute -top-1 -right-1 flex h-4 w-4">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-4 w-4 rounded-full bg-emerald-500 border-2 border-white" />
            </span>
          </button>
        </div>
      )}

      {/* Chat Window Panel */}
      {isOpen && (
        <div
          className={`fixed z-50 transition-all duration-300 ease-in-out flex flex-col overflow-hidden bg-white shadow-2xl border border-slate-200/90 ${
            isExpanded
              ? 'inset-2 sm:inset-6 rounded-2xl'
              : 'bottom-4 right-4 sm:bottom-6 sm:right-6 w-[95vw] sm:w-[480px] h-[650px] max-h-[90vh] rounded-2xl'
          }`}
          role="dialog"
          aria-label="TRACE-X Assistant Window"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-200 bg-gradient-to-r from-slate-900 via-slate-850 to-blue-950 px-4 py-3.5 text-white">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600/90 text-white shadow-sm ring-2 ring-blue-400/30">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm tracking-tight">TRACE-X Assistant</span>
                  <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Online
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-slate-300">
                  <span>Cyber-Forensics AI Copilot</span>
                  {activeCase && (
                    <span className="text-blue-300 font-mono text-[10px]">
                      • Context: {activeCase.caseId}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Header controls */}
            <div className="flex items-center gap-1.5 text-slate-300">
              <button
                onClick={() => setShowClearConfirm(true)}
                className="rounded-lg p-1.5 hover:bg-white/10 hover:text-white transition-colors"
                title="Clear conversation"
                aria-label="Clear conversation history"
              >
                <Trash2 className="h-4 w-4" />
              </button>
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="rounded-lg p-1.5 hover:bg-white/10 hover:text-white transition-colors hidden sm:block"
                title={isExpanded ? 'Restore window size' : 'Expand full window'}
                aria-label={isExpanded ? 'Restore size' : 'Expand window'}
              >
                {isExpanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="rounded-lg p-1.5 hover:bg-white/10 hover:text-white transition-colors"
                title="Close chat"
                aria-label="Close chat window"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* Active case context banner */}
          {activeCase && (
            <div className="flex items-center justify-between bg-blue-50/90 border-b border-blue-100 px-4 py-2 text-xs text-blue-900">
              <div className="flex items-center gap-2 truncate">
                <span className="font-bold text-blue-800">Active Dossier:</span>
                <span className="font-mono bg-blue-100 text-blue-800 px-1.5 py-0.5 rounded text-[10px] font-bold">
                  {activeCase.caseId}
                </span>
                <span className="truncate text-slate-600 font-medium">
                  {activeCase.subject}
                </span>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold whitespace-nowrap ${
                activeCase.verdict === 'Critical Threat'
                  ? 'bg-red-100 text-red-800'
                  : activeCase.verdict === 'High Risk'
                  ? 'bg-amber-100 text-amber-800'
                  : 'bg-emerald-100 text-emerald-800'
              }`}>
                {activeCase.verdict} ({activeCase.riskScore}/100)
              </span>
            </div>
          )}

          {/* Clear confirmation alert banner */}
          {showClearConfirm && (
            <div className="flex items-center justify-between bg-amber-50 border-b border-amber-200 px-4 py-2 text-xs text-amber-900 animate-in fade-in">
              <span>Clear entire conversation history?</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleClearChat}
                  className="rounded bg-amber-700 px-2 py-1 text-[11px] font-bold text-white hover:bg-amber-800"
                >
                  Yes, Clear
                </button>
                <button
                  onClick={() => setShowClearConfirm(false)}
                  className="rounded bg-slate-200 px-2 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-300"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Message Thread */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-50/60">
            {messages.map((msg) => {
              const isAssistant = msg.sender === 'assistant';

              return (
                <div
                  key={msg.id}
                  className={`flex items-start gap-2.5 ${isAssistant ? '' : 'flex-row-reverse'}`}
                >
                  {/* Avatar */}
                  <div
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-xl text-xs font-semibold shadow-xs ${
                      isAssistant
                        ? 'bg-blue-600 text-white shadow-blue-500/20'
                        : 'bg-slate-800 text-white'
                    }`}
                  >
                    {isAssistant ? <Bot className="h-4 w-4" /> : <User className="h-4 w-4" />}
                  </div>

                  {/* Message Bubble */}
                  <div
                    className={`flex flex-col max-w-[85%] sm:max-w-[80%] rounded-2xl p-3.5 text-xs shadow-xs ${
                      isAssistant
                        ? 'bg-white border border-slate-200/90 text-slate-800'
                        : 'bg-blue-600 text-white'
                    }`}
                  >
                    {/* Header info */}
                    <div
                      className={`flex items-center justify-between gap-3 mb-1.5 text-[10px] ${
                        isAssistant ? 'text-slate-400' : 'text-blue-100'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-semibold">
                        <span>{isAssistant ? 'TRACE-X Assistant' : 'You (Analyst)'}</span>
                        {isAssistant && msg.mode && (
                          <span
                            className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                              msg.mode === 'ai_llm'
                                ? 'bg-purple-100 text-purple-700'
                                : 'bg-blue-100 text-blue-700'
                            }`}
                          >
                            {msg.mode === 'ai_llm' ? 'AI LLM' : 'Forensic Engine'}
                          </span>
                        )}
                      </div>
                      <span>{msg.timestamp}</span>
                    </div>

                    {/* Content */}
                    <div className="whitespace-pre-line leading-relaxed font-sans prose prose-xs max-w-none">
                      {msg.text}
                    </div>

                    {/* Interactive Action Buttons */}
                    {isAssistant && msg.actions && msg.actions.length > 0 && (
                      <div className="mt-3 flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-100">
                        <span className="text-[10px] font-semibold text-slate-500 mr-1 flex items-center gap-1">
                          <Compass className="w-3 h-3 text-blue-600" /> Actions:
                        </span>
                        {msg.actions.map((act, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleActionClick(act.action)}
                            className="inline-flex items-center gap-1 rounded-lg bg-blue-50 border border-blue-200 px-2.5 py-1 text-[11px] font-bold text-blue-700 hover:bg-blue-600 hover:text-white hover:border-blue-600 transition-all shadow-xs"
                          >
                            <span>{act.label}</span>
                            <ArrowRight className="h-3 w-3" />
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Suggested follow-up queries */}
                    {isAssistant && msg.suggestedQuestions && msg.suggestedQuestions.length > 0 && (
                      <div className="mt-2.5 space-y-1 pt-2 border-t border-slate-100">
                        <div className="text-[10px] font-semibold text-slate-400 flex items-center gap-1">
                          <Sparkles className="w-3 h-3 text-amber-500" /> Suggested questions:
                        </div>
                        <div className="flex flex-col gap-1">
                          {msg.suggestedQuestions.slice(0, 3).map((sq, i) => (
                            <button
                              key={i}
                              onClick={() => handleSendMessage(sq)}
                              className="text-left text-[11px] text-blue-600 hover:text-blue-800 hover:underline flex items-center gap-1 transition-colors"
                            >
                              <ChevronRight className="w-3 h-3 shrink-0 text-slate-400" />
                              <span className="truncate">{sq}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Disclaimer note */}
                    {isAssistant && msg.disclaimer && (
                      <div className="mt-2 text-[10px] text-slate-400 italic pt-1 border-t border-slate-100">
                        {msg.disclaimer}
                      </div>
                    )}

                    {/* Bottom tools (Copy & Retry) */}
                    {isAssistant && (
                      <div className="mt-2 flex items-center justify-between pt-1 text-[10px] text-slate-400 border-t border-slate-50">
                        <span className="text-[10px] font-mono opacity-80">
                          {msg.provider || 'TRACE-X'}
                        </span>
                        <div className="flex items-center gap-2">
                          {msg.failed && (
                            <button
                              onClick={handleRetryLast}
                              className="inline-flex items-center gap-1 text-red-600 font-bold hover:underline"
                            >
                              <RotateCcw className="w-3 h-3" /> Retry
                            </button>
                          )}
                          <button
                            onClick={() => handleCopy(msg.id, msg.text)}
                            className="inline-flex items-center gap-1 hover:text-slate-700 transition-colors"
                            title="Copy response"
                          >
                            {copiedMessageId === msg.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-600" />
                                <span className="text-emerald-600 font-semibold">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {/* Processing Indicator */}
            {isProcessing && (
              <div className="flex items-start gap-2.5 animate-in fade-in">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-blue-600 text-white shadow-xs">
                  <Bot className="h-4 w-4" />
                </div>
                <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-xs">
                  <div className="flex items-center gap-2 text-xs text-slate-500 font-medium">
                    <span className="flex h-2 w-2 rounded-full bg-blue-600 animate-ping" />
                    <span>TRACE-X Assistant analyzing telemetry & RFC rules...</span>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Suggested Quick Prompt Chips Bar */}
          <div className="border-t border-slate-100 bg-white px-3 py-2 overflow-x-auto whitespace-nowrap scrollbar-thin">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-blue-600" /> Quick:
              </span>
              {quickCategories.map((chip, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(chip.query)}
                  className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-200 transition-all shrink-0"
                >
                  {chip.label}
                </button>
              ))}
            </div>
          </div>

          {/* Input Form Bar */}
          <div className="border-t border-slate-200 bg-white p-3">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="flex items-end gap-2"
            >
              <div className="relative flex-1">
                <textarea
                  ref={textareaRef}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask TRACE-X (e.g., Is this email phishing? Explain Return-Path...)"
                  rows={1}
                  className="w-full resize-none rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all max-h-28"
                  style={{ minHeight: '38px' }}
                />
              </div>

              <button
                type="submit"
                disabled={!inputValue.trim() || isProcessing}
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-blue-600 text-white shadow-sm hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all focus:outline-none focus:ring-2 focus:ring-blue-400"
                aria-label="Send query"
              >
                <Send className="h-4 w-4" />
              </button>
            </form>
            <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-400 px-1">
              <span>Press <strong>Enter</strong> to send • <strong>Shift+Enter</strong> for newline</span>
              <span className="font-medium text-slate-500">TRACE-X Intelligence v2.4</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
