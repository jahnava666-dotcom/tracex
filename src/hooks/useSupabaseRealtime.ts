import { useEffect, useRef } from 'react';
import { supabase } from '../lib/supabase';
import { RealtimeChannel } from '@supabase/supabase-js';

interface RealtimeSubscriptionOptions {
  table: 'investigations' | 'email_analyses' | 'evidence' | 'indicators_of_compromise' | 'audit_logs';
  onInsert?: (payload: any) => void;
  onUpdate?: (payload: any) => void;
  onDelete?: (payload: any) => void;
  filter?: string;
  enabled?: boolean;
}

/**
 * Reusable Supabase Realtime subscription hook with error recovery and cleanup
 */
export function useSupabaseRealtime({
  table,
  onInsert,
  onUpdate,
  onDelete,
  filter,
  enabled = true
}: RealtimeSubscriptionOptions) {
  const channelRef = useRef<RealtimeChannel | null>(null);

  useEffect(() => {
    if (!enabled) return;

    const channelName = `realtime-${table}-${Math.random().toString(36).substring(2, 8)}`;
    const channel = supabase.channel(channelName);

    channel
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table,
          filter
        },
        (payload) => {
          if (onInsert) onInsert(payload.new);
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table,
          filter
        },
        (payload) => {
          if (onUpdate) onUpdate(payload.new);
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'DELETE',
          schema: 'public',
          table,
          filter
        },
        (payload) => {
          if (onDelete) onDelete(payload.old);
        }
      )
      .subscribe((status, err) => {
        if (err) {
          console.warn(`[TRACE-X Realtime] Error on ${table}:`, err.message);
        }
      });

    channelRef.current = channel;

    return () => {
      if (channelRef.current) {
        supabase.removeChannel(channelRef.current);
        channelRef.current = null;
      }
    };
  }, [table, filter, enabled]);
}
