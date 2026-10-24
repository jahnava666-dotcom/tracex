-- 20260910000000_trace_x_schema.sql
-- Migration mirroring supabase/schema.sql
-- See supabase/schema.sql for documentation and comments.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('analyst', 'senior_analyst', 'lead_investigator', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (id, full_name, role)
    VALUES (
        new.id,
        COALESCE(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
        'analyst'
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE OR REPLACE FUNCTION public.protect_profile_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.role IS DISTINCT FROM NEW.role THEN
        IF auth.uid() IS NOT NULL AND OLD.role != 'admin' THEN
            NEW.role := OLD.role;
        END IF;
    END IF;
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_profile_role ON public.profiles;
CREATE TRIGGER trg_protect_profile_role
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.protect_profile_role();

CREATE TABLE IF NOT EXISTS public.email_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE DEFAULT auth.uid(),
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence NUMERIC NOT NULL DEFAULT 85 CHECK (confidence >= 0 AND confidence <= 100),
    status TEXT NOT NULL DEFAULT 'completed',
    analysis_results JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TABLE IF NOT EXISTS public.investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE DEFAULT auth.uid(),
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Review', 'Mitigated', 'Closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE OR REPLACE FUNCTION public.handle_investigation_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_investigation_updated_at ON public.investigations;
CREATE TRIGGER trg_investigation_updated_at
    BEFORE UPDATE ON public.investigations
    FOR EACH ROW EXECUTE FUNCTION public.handle_investigation_updated_at();

CREATE TABLE IF NOT EXISTS public.evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE DEFAULT auth.uid(),
    evidence_type TEXT NOT NULL,
    description TEXT,
    source TEXT,
    sha256_hash TEXT NOT NULL,
    integrity_status TEXT NOT NULL DEFAULT 'verified' CHECK (integrity_status IN ('verified', 'unverified', 'tampered', 'pending')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TABLE IF NOT EXISTS public.indicators_of_compromise (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('Domain', 'IP', 'URL', 'Attachment', 'SHA-256')),
    indicator_value TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('Clean', 'Suspicious', 'Malicious', 'High', 'Critical')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT uq_investigation_indicator UNIQUE (investigation_id, indicator_type, indicator_value)
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE DEFAULT auth.uid(),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_email_analyses_user ON public.email_analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_email_analyses_created_at ON public.email_analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_analyses_threat_type ON public.email_analyses(threat_type);
CREATE INDEX IF NOT EXISTS idx_investigations_user ON public.investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_investigations_case_number ON public.investigations(case_number);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON public.investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON public.investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON public.evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_user ON public.evidence(user_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON public.evidence(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_iocs_investigation ON public.indicators_of_compromise(investigation_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON public.indicators_of_compromise(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON public.audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.indicators_of_compromise ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Authenticated users can view team profiles" ON public.profiles;
CREATE POLICY "Authenticated users can view team profiles"
    ON public.profiles FOR SELECT
    TO authenticated
    USING (true);

DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
CREATE POLICY "Users can update their own profile"
    ON public.profiles FOR UPDATE
    TO authenticated
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "Users can view their own email analyses" ON public.email_analyses;
CREATE POLICY "Users can view their own email analyses"
    ON public.email_analyses FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert email analyses" ON public.email_analyses;
CREATE POLICY "Users can insert email analyses"
    ON public.email_analyses FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own email analyses" ON public.email_analyses;
CREATE POLICY "Users can update their own email analyses"
    ON public.email_analyses FOR UPDATE
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own email analyses" ON public.email_analyses;
CREATE POLICY "Users can delete their own email analyses"
    ON public.email_analyses FOR DELETE
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view their own investigations" ON public.investigations;
CREATE POLICY "Users can view their own investigations"
    ON public.investigations FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert investigations" ON public.investigations;
CREATE POLICY "Users can insert investigations"
    ON public.investigations FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own investigations" ON public.investigations;
CREATE POLICY "Users can update their own investigations"
    ON public.investigations FOR UPDATE
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own investigations" ON public.investigations;
CREATE POLICY "Users can delete their own investigations"
    ON public.investigations FOR DELETE
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view evidence for authorized investigations" ON public.evidence;
CREATE POLICY "Users can view evidence for authorized investigations"
    ON public.evidence FOR SELECT
    TO authenticated
    USING (
        auth.uid() = user_id OR
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = evidence.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can insert evidence for their investigations" ON public.evidence;
CREATE POLICY "Users can insert evidence for their investigations"
    ON public.evidence FOR INSERT
    TO authenticated
    WITH CHECK (
        auth.uid() = user_id AND
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = evidence.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can update evidence for their investigations" ON public.evidence;
CREATE POLICY "Users can update evidence for their investigations"
    ON public.evidence FOR UPDATE
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete evidence for their investigations" ON public.evidence;
CREATE POLICY "Users can delete evidence for their investigations"
    ON public.evidence FOR DELETE
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view IOCs for their investigations" ON public.indicators_of_compromise;
CREATE POLICY "Users can view IOCs for their investigations"
    ON public.indicators_of_compromise FOR SELECT
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = indicators_of_compromise.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can insert IOCs for their investigations" ON public.indicators_of_compromise;
CREATE POLICY "Users can insert IOCs for their investigations"
    ON public.indicators_of_compromise FOR INSERT
    TO authenticated
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = indicators_of_compromise.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can update IOCs for their investigations" ON public.indicators_of_compromise;
CREATE POLICY "Users can update IOCs for their investigations"
    ON public.indicators_of_compromise FOR UPDATE
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = indicators_of_compromise.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can delete IOCs for their investigations" ON public.indicators_of_compromise;
CREATE POLICY "Users can delete IOCs for their investigations"
    ON public.indicators_of_compromise FOR DELETE
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM public.investigations i
            WHERE i.id = indicators_of_compromise.investigation_id AND i.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can view their audit logs" ON public.audit_logs;
CREATE POLICY "Users can view their audit logs"
    ON public.audit_logs FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert audit logs" ON public.audit_logs;
CREATE POLICY "Users can insert audit logs"
    ON public.audit_logs FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = user_id);
