import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, Lock, Mail, User, X, AlertCircle, CheckCircle2, Loader2, ArrowRight } from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'signin' | 'signup' | 'reset';
  onSuccess?: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  initialMode = 'signin',
  onSuccess
}) => {
  const { signIn, signUp, resetPassword } = useAuth();
  const [mode, setMode] = useState<'signin' | 'signup' | 'reset'>(initialMode);
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      if (mode === 'signin') {
        if (!email || !password) {
          setErrorMsg('Please enter both email and password.');
          setLoading(false);
          return;
        }

        const { error } = await signIn(email, password);
        if (error) {
          setErrorMsg(error.message);
        } else {
          setSuccessMsg('Authentication successful! Welcome to TRACE-X SOC.');
          setTimeout(() => {
            onClose();
            if (onSuccess) onSuccess();
          }, 600);
        }
      } else if (mode === 'signup') {
        if (!email || !password || !fullName) {
          setErrorMsg('All fields are required for analyst onboarding.');
          setLoading(false);
          return;
        }

        if (password.length < 6) {
          setErrorMsg('Password must be at least 6 characters.');
          setLoading(false);
          return;
        }

        const { error, user } = await signUp(email, password, fullName);
        if (error) {
          setErrorMsg(error.message);
        } else {
          if (user?.identities?.length === 0) {
            setErrorMsg('An account with this email already exists.');
          } else {
            setSuccessMsg(
              'Account created successfully! If email confirmation is enabled on your Supabase project, check your inbox.'
            );
            setTimeout(() => {
              onClose();
              if (onSuccess) onSuccess();
            }, 1200);
          }
        }
      } else if (mode === 'reset') {
        if (!email) {
          setErrorMsg('Please provide your corporate email address.');
          setLoading(false);
          return;
        }

        const { error } = await resetPassword(email);
        if (error) {
          setErrorMsg(error.message);
        } else {
          setSuccessMsg('Password reset instructions dispatched to your email.');
        }
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'An unexpected error occurred.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-2xl shadow-slate-900/20">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
          aria-label="Close authentication modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="text-center mb-6">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-blue-600 text-white shadow-md shadow-blue-500/25 mb-3">
            <Shield className="h-6 w-6" />
          </div>
          <h2 className="text-xl font-extrabold text-slate-900 tracking-tight">
            {mode === 'signin' && 'Analyst Access Portal'}
            {mode === 'signup' && 'Register SOC Investigator'}
            {mode === 'reset' && 'Reset Access Password'}
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            {mode === 'signin' && 'Sign in to access encrypted forensic cases and threat telemetry'}
            {mode === 'signup' && 'Create your verified analyst account to sync email threat dossiers'}
            {mode === 'reset' && 'Enter your verified email to receive a recovery link'}
          </p>
        </div>

        {/* Feedback Alerts */}
        {errorMsg && (
          <div className="mb-4 flex items-start gap-2.5 rounded-xl border border-red-200 bg-red-50/80 p-3 text-xs text-red-700">
            <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
            <div>{errorMsg}</div>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 flex items-start gap-2.5 rounded-xl border border-emerald-200 bg-emerald-50/80 p-3 text-xs text-emerald-800">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
            <div>{successMsg}</div>
          </div>
        )}

        {/* Mode Selector Tabs */}
        {mode !== 'reset' && (
          <div className="grid grid-cols-2 gap-1 rounded-xl bg-slate-100 p-1 mb-5 text-xs font-semibold">
            <button
              type="button"
              onClick={() => {
                setMode('signin');
                setErrorMsg(null);
                setSuccessMsg(null);
              }}
              className={`rounded-lg py-2 transition-all ${
                mode === 'signin'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('signup');
                setErrorMsg(null);
                setSuccessMsg(null);
              }}
              className={`rounded-lg py-2 transition-all ${
                mode === 'signup'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Sign Up
            </button>
          </div>
        )}

        {/* Auth Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {mode === 'signup' && (
            <div>
              <label className="block font-semibold text-slate-700 mb-1">Analyst Full Name</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Alex Carter"
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-9 pr-3 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block font-semibold text-slate-700 mb-1">Corporate Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc-defense.com"
                className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-9 pr-3 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100"
              />
            </div>
          </div>

          {mode !== 'reset' && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block font-semibold text-slate-700">Password</label>
                {mode === 'signin' && (
                  <button
                    type="button"
                    onClick={() => {
                      setMode('reset');
                      setErrorMsg(null);
                      setSuccessMsg(null);
                    }}
                    className="text-[11px] text-blue-600 hover:text-blue-700 font-semibold"
                  >
                    Forgot password?
                  </button>
                )}
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-9 pr-3 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-100"
                />
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 py-3 text-xs font-bold text-white shadow-md shadow-blue-600/25 hover:bg-blue-700 disabled:opacity-60 transition-all cursor-pointer"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <span>
                  {mode === 'signin' && 'Sign In to Workspace'}
                  {mode === 'signup' && 'Create Analyst Account'}
                  {mode === 'reset' && 'Send Reset Instructions'}
                </span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {mode === 'reset' && (
          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={() => {
                setMode('signin');
                setErrorMsg(null);
                setSuccessMsg(null);
              }}
              className="text-xs font-semibold text-slate-600 hover:text-slate-900"
            >
              ← Back to Sign In
            </button>
          </div>
        )}

        {/* Security watermark */}
        <div className="mt-6 pt-4 border-t border-slate-100 text-center">
          <span className="text-[10px] text-slate-400 font-mono">
            Secured by Supabase Auth • Row Level Security Enforced
          </span>
        </div>
      </div>
    </div>
  );
};
