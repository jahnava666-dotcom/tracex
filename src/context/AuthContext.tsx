import React, { createContext, useContext, useEffect, useState, useMemo } from 'react';
import { User, Session, AuthError } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';

export interface UserProfile {
  id: string;
  full_name: string | null;
  role: string;
  created_at?: string;
}

interface AuthContextType {
  user: User | null;
  session: Session | null;
  profile: UserProfile | null;
  isLoading: boolean;
  isConfigured: boolean;
  signIn: (email: string, password: string) => Promise<{ error: AuthError | Error | null }>;
  signUp: (email: string, password: string, fullName: string) => Promise<{ error: AuthError | Error | null; user?: User | null }>;
  signOut: () => Promise<void>;
  resetPassword: (email: string) => Promise<{ error: AuthError | Error | null }>;
  updateProfileName: (fullName: string) => Promise<{ error: Error | null }>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const isConfigured = Boolean(
    import.meta.env.VITE_SUPABASE_URL && import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY
  );

  const fetchProfile = async (userId: string, email?: string, userMetadata?: Record<string, any>) => {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

      if (!error && data) {
        setProfile(data as UserProfile);
        return;
      }

      // If profiles table does not exist or user doesn't have a row yet, synthesize safe profile from auth metadata
      const fallbackName = userMetadata?.full_name || email?.split('@')[0] || 'Security Analyst';
      setProfile({
        id: userId,
        full_name: fallbackName,
        role: 'analyst',
        created_at: new Date().toISOString()
      });
    } catch {
      const fallbackName = userMetadata?.full_name || email?.split('@')[0] || 'Security Analyst';
      setProfile({
        id: userId,
        full_name: fallbackName,
        role: 'analyst',
        created_at: new Date().toISOString()
      });
    }
  };

  useEffect(() => {
    let mounted = true;

    async function initializeAuth() {
      try {
        const { data, error } = await supabase.auth.getSession();
        if (error) {
          console.warn('[TRACE-X Auth] getSession error:', error.message);
        }

        if (mounted) {
          setSession(data.session);
          setUser(data.session?.user ?? null);
          if (data.session?.user) {
            await fetchProfile(
              data.session.user.id,
              data.session.user.email,
              data.session.user.user_metadata
            );
          }
        }
      } catch (err) {
        console.warn('[TRACE-X Auth] Init exception:', err);
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    initializeAuth();

    const { data: authListener } = supabase.auth.onAuthStateChange(
      async (event, currentSession) => {
        if (!mounted) return;
        setSession(currentSession);
        setUser(currentSession?.user ?? null);

        if (currentSession?.user) {
          await fetchProfile(
            currentSession.user.id,
            currentSession.user.email,
            currentSession.user.user_metadata
          );
        } else {
          setProfile(null);
        }
        setIsLoading(false);
      }
    );

    return () => {
      mounted = false;
      authListener.subscription.unsubscribe();
    };
  }, []);

  const signIn = async (email: string, password: string) => {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password
      });

      if (error) {
        return { error };
      }

      // Log audit trail event if possible
      if (data.user) {
        try {
          await supabase.from('audit_logs').insert({
            user_id: data.user.id,
            action: 'USER_LOGIN',
            resource_type: 'AUTH_SESSION',
            resource_id: data.user.id,
            metadata: {
              timestamp: new Date().toISOString(),
              client: 'TRACE-X Web Forensics'
            }
          });
        } catch {
          // Non-blocking if table is not yet migrated
        }
      }

      return { error: null };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err : new Error(String(err)) };
    }
  };

  const signUp = async (email: string, password: string, fullName: string) => {
    try {
      const { data, error } = await supabase.auth.signUp({
        email: email.trim(),
        password,
        options: {
          data: {
            full_name: fullName.trim()
          }
        }
      });

      if (error) {
        return { error };
      }

      // Try creating profile row directly in case database trigger is not yet installed
      if (data.user) {
        try {
          await supabase.from('profiles').insert({
            id: data.user.id,
            full_name: fullName.trim(),
            role: 'analyst'
          });
        } catch {
          // Trigger or RLS may handle it
        }

        try {
          await supabase.from('audit_logs').insert({
            user_id: data.user.id,
            action: 'USER_SIGNUP',
            resource_type: 'AUTH_SESSION',
            resource_id: data.user.id,
            metadata: {
              timestamp: new Date().toISOString(),
              fullName: fullName.trim()
            }
          });
        } catch {
          // Non-blocking
        }
      }

      return { error: null, user: data.user };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err : new Error(String(err)) };
    }
  };

  const signOut = async () => {
    if (user) {
      try {
        await supabase.from('audit_logs').insert({
          user_id: user.id,
          action: 'USER_LOGOUT',
          resource_type: 'AUTH_SESSION',
          resource_id: user.id,
          metadata: { timestamp: new Date().toISOString() }
        });
      } catch {
        // Non-blocking
      }
    }
    await supabase.auth.signOut();
    setUser(null);
    setSession(null);
    setProfile(null);
  };

  const resetPassword = async (email: string) => {
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
        redirectTo: window.location.origin
      });
      return { error };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err : new Error(String(err)) };
    }
  };

  const updateProfileName = async (fullName: string) => {
    if (!user) return { error: new Error('User not authenticated') };

    try {
      // 1. Update auth metadata
      const { error: userError } = await supabase.auth.updateUser({
        data: { full_name: fullName.trim() }
      });
      if (userError) throw userError;

      // 2. Update profiles table if available
      const { error: profileError } = await supabase
        .from('profiles')
        .update({ full_name: fullName.trim() })
        .eq('id', user.id);

      if (!profileError) {
        setProfile((prev) => (prev ? { ...prev, full_name: fullName.trim() } : null));
      }

      return { error: null };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err : new Error(String(err)) };
    }
  };

  const value = useMemo(
    () => ({
      user,
      session,
      profile,
      isLoading,
      isConfigured,
      signIn,
      signUp,
      signOut,
      resetPassword,
      updateProfileName
    }),
    [user, session, profile, isLoading, isConfigured]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
