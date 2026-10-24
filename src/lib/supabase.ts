import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabasePublishableKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

if (!supabaseUrl || !supabasePublishableKey) {
  console.warn(
    '[TRACE-X] Missing Supabase environment variables. Please check VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in .env.local'
  );
}

export const supabase = createClient(
  supabaseUrl || 'https://placeholder-url.supabase.co',
  supabasePublishableKey || 'placeholder-anon-key',
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      storageKey: 'tracex-auth-session'
    },
    realtime: {
      params: {
        eventsPerSecond: 10
      }
    }
  }
);

/**
 * Utility to test whether the active Supabase connection is reachable.
 */
export async function testSupabaseConnection(): Promise<{
  connected: boolean;
  message: string;
  userEmail?: string | null;
}> {
  try {
    if (!supabaseUrl || !supabasePublishableKey) {
      return {
        connected: false,
        message: 'Supabase credentials missing in .env.local'
      };
    }

    // Check auth session
    const { data: authData, error: authError } = await supabase.auth.getSession();
    if (authError) {
      return {
        connected: false,
        message: `Auth check failed: ${authError.message}`
      };
    }

    // Check basic query to confirm API reachability
    const { error: queryError } = await supabase
      .from('profiles')
      .select('count', { count: 'exact', head: true });

    if (queryError) {
      // If table doesn't exist yet (404/PGRST205), connection to Supabase itself succeeded
      if (
        queryError.code === 'PGRST205' ||
        queryError.message?.includes('not found') ||
        queryError.code === '42P01'
      ) {
        return {
          connected: true,
          message: 'Connected to Supabase project (Tables pending SQL schema migration)',
          userEmail: authData.session?.user?.email
        };
      }
      return {
        connected: true,
        message: `Connected: ${queryError.message}`,
        userEmail: authData.session?.user?.email
      };
    }

    return {
      connected: true,
      message: 'Connected to Supabase project and database schema active',
      userEmail: authData.session?.user?.email
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      connected: false,
      message: `Connection error: ${errorMsg}`
    };
  }
}
