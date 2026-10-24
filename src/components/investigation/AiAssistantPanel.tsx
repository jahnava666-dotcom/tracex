import React, { useState, useRef, useEffect } from 'react';
import { EmailInvestigationCase, AssistantMessage } from '../../types/forensics';
import { apiClient } from '../../api/client';
import { Bot, Send, User, Sparkles, CornerDownLeft, ShieldCheck, Terminal } from 'lucide-react';

interface AiAssistantPanelProps {
  caseData: EmailInvestigationCase;
}

export const AiAssistantPanel: React.FC<AiAssistantPanelProps> = ({ caseData }) => {
  const [messages, setMessages] = useState<AssistantMessage[]>([
    {
      id: 'm-1',
      sender: 'investigator',
      text: 'Why was this email classified as malicious?',
      timestamp: '10:33 AM'
    },
    {
      id: 'm-2',
      sender: 'ai',
      text: 'The email shows a DMARC alignment failure, a visually similar sender domain, a suspicious URL redirect and suspicious infrastructure indicators.',
      timestamp: '10:33 AM'
    },
    {
      id: 'm-3',
      sender: 'investigator',
      text: 'What should I investigate next?',
      timestamp: '10:34 AM'
    },
    {
      id: 'm-4',
      sender: 'ai',
      text: 'Investigate the destination domain, search recent email logs for the URL, check the extracted IP against security logs, and compare the sender with known legitimate communications.',
      timestamp: '10:34 AM'
    }
  ]);

  const [inputQuery, setInputQuery] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const promptSuggestions = [
    'Explain DMARC failure',
    'Is the attachment dangerous?',
    'What is the recommended mitigation?'
  ];

  const handleSendMessage = async (queryText?: string) => {
    const textToSend = queryText || inputQuery;
    if (!textToSend.trim() || isTyping) return;

    const userMsg: AssistantMessage = {
      id: `usr-${Date.now()}`,
      sender: 'investigator',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!queryText) setInputQuery('');
    setIsTyping(true);

    try {
      const chatRes = await apiClient.sendChatMessage(textToSend, `panel-${caseData.caseId}`, {
        current_page: 'results',
        case_id: caseData.caseId,
        case_data: caseData
      });
      const aiMsg: AssistantMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: chatRes.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      console.error(err);
    } finally {
      setIsTyping(false);
    }
  };

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-slate-100 pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-600 text-white shadow-sm shadow-blue-500/20">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-900">TRACE-X Assistant</h2>
              <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded-full">
                Context Active ({caseData.caseId})
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Forensic copilot trained on email headers, RFC standards, and cyber threat intelligence.
            </p>
          </div>
        </div>
      </div>

      {/* Conversation Thread */}
      <div className="space-y-3.5 max-h-80 overflow-y-auto pr-1 p-2 bg-slate-50/70 rounded-xl border border-slate-100">
        {messages.map((m) => {
          const isAi = m.sender === 'ai';
          return (
            <div
              key={m.id}
              className={`flex items-start gap-2.5 ${isAi ? '' : 'flex-row-reverse'}`}
            >
              {/* Avatar */}
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-xs flex-shrink-0 ${
                  isAi
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-white'
                }`}
              >
                {isAi ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
              </div>

              {/* Bubble */}
              <div
                className={`max-w-[85%] rounded-2xl px-4 py-2.5 text-xs shadow-sm ${
                  isAi
                    ? 'bg-white text-slate-800 border border-slate-200 leading-relaxed'
                    : 'bg-blue-600 text-white leading-relaxed'
                }`}
              >
                <div className="flex items-center justify-between gap-4 mb-1 text-[10px] opacity-70">
                  <span className="font-semibold">{isAi ? 'Forensic AI' : 'Investigator (You)'}</span>
                  <span>{m.timestamp}</span>
                </div>
                <div className="whitespace-pre-line">{m.text}</div>
              </div>
            </div>
          );
        })}

        {isTyping && (
          <div className="flex items-center gap-2 text-xs text-slate-400 italic pl-10">
            <Bot className="w-3.5 h-3.5 animate-bounce text-blue-600" />
            <span>AI Copilot analyzing investigation telemetry...</span>
          </div>
        )}
        <div ref={chatBottomRef} />
      </div>

      {/* Suggested Prompt Chips */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-blue-600" /> Quick Inquiries:
        </span>
        {promptSuggestions.map((suggestion, i) => (
          <button
            key={i}
            onClick={() => handleSendMessage(suggestion)}
            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-200 transition-all shadow-xs"
          >
            {suggestion}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="flex items-center gap-2 pt-2"
      >
        <div className="relative flex-1">
          <input
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            placeholder="Ask about this investigation..."
            className="w-full rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all"
          />
        </div>
        <button
          type="submit"
          disabled={!inputQuery.trim() || isTyping}
          className="inline-flex items-center gap-1.5 rounded-xl bg-blue-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          <Send className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Send</span>
        </button>
      </form>
    </div>
  );
};
