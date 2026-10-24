export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          full_name: string | null;
          role: string;
          created_at: string;
        };
        Insert: {
          id: string;
          full_name?: string | null;
          role?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          full_name?: string | null;
          role?: string;
          created_at?: string;
        };
      };
      email_analyses: {
        Row: {
          id: string;
          user_id: string;
          sender: string;
          subject: string;
          threat_type: string;
          risk_score: number;
          confidence: number;
          status: string;
          analysis_results: Json;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id?: string;
          sender: string;
          subject: string;
          threat_type: string;
          risk_score: number;
          confidence: number;
          status?: string;
          analysis_results?: Json;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          sender?: string;
          subject?: string;
          threat_type?: string;
          risk_score?: number;
          confidence?: number;
          status?: string;
          analysis_results?: Json;
          created_at?: string;
        };
      };
      investigations: {
        Row: {
          id: string;
          user_id: string;
          case_number: string;
          title: string;
          description: string | null;
          severity: string;
          status: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id?: string;
          case_number: string;
          title: string;
          description?: string | null;
          severity: string;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          case_number?: string;
          title?: string;
          description?: string | null;
          severity?: string;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      evidence: {
        Row: {
          id: string;
          investigation_id: string;
          user_id: string;
          evidence_type: string;
          description: string | null;
          source: string | null;
          sha256_hash: string;
          integrity_status: string;
          metadata: Json;
          created_at: string;
        };
        Insert: {
          id?: string;
          investigation_id: string;
          user_id?: string;
          evidence_type: string;
          description?: string | null;
          source?: string | null;
          sha256_hash: string;
          integrity_status?: string;
          metadata?: Json;
          created_at?: string;
        };
        Update: {
          id?: string;
          investigation_id?: string;
          user_id?: string;
          evidence_type?: string;
          description?: string | null;
          source?: string | null;
          sha256_hash?: string;
          integrity_status?: string;
          metadata?: Json;
          created_at?: string;
        };
      };
      indicators_of_compromise: {
        Row: {
          id: string;
          investigation_id: string;
          indicator_type: string;
          indicator_value: string;
          risk_level: string;
          metadata: Json;
          created_at: string;
        };
        Insert: {
          id?: string;
          investigation_id: string;
          indicator_type: string;
          indicator_value: string;
          risk_level: string;
          metadata?: Json;
          created_at?: string;
        };
        Update: {
          id?: string;
          investigation_id?: string;
          indicator_type?: string;
          indicator_value?: string;
          risk_level?: string;
          metadata?: Json;
          created_at?: string;
        };
      };
      audit_logs: {
        Row: {
          id: string;
          user_id: string;
          action: string;
          resource_type: string;
          resource_id: string | null;
          metadata: Json;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id?: string;
          action: string;
          resource_type: string;
          resource_id?: string | null;
          metadata?: Json;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          action?: string;
          resource_type?: string;
          resource_id?: string | null;
          metadata?: Json;
          created_at?: string;
        };
      };
    };
  };
}
