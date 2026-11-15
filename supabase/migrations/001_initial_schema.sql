
-- =========================================
-- LOP 9/2 - DATABASE SCHEMA V1
-- =========================================

-- 1. GROUPS
CREATE TABLE public.groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.groups (name)
VALUES ('Tổ 1'), ('Tổ 2'), ('Tổ 3'), ('Tổ 4');

-- 2. PROFILES
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN (
            'student',
            'teacher',
            'class_president',
            'academic_monitor',
            'labor_monitor',
            'group_leader'
        )),
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. GROUP MEMBERS
CREATE TABLE public.group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    is_leader BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (group_id, student_id),
    UNIQUE (student_id)
);

-- 4. SCORE EVENTS
CREATE TABLE public.score_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES public.profiles(id),
    event_type TEXT NOT NULL,
    points INTEGER NOT NULL,
    description TEXT,
    created_by UUID REFERENCES public.profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. CHORES
CREATE TABLE public.chores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES public.groups(id),
    assigned_to UUID REFERENCES public.profiles(id),
    duty_date DATE NOT NULL,
    area TEXT NOT NULL,
    task TEXT NOT NULL,
    is_exempt BOOLEAN NOT NULL DEFAULT FALSE,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. NOTIFICATIONS
CREATE TABLE public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_id UUID REFERENCES public.profiles(id),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. AUDIT LOGS
CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.profiles(id),
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. INDEXES
CREATE INDEX idx_group_members_group
ON public.group_members(group_id);

CREATE INDEX idx_score_events_student
ON public.score_events(student_id);

CREATE INDEX idx_chores_date
ON public.chores(duty_date);

CREATE INDEX idx_notifications_recipient
ON public.notifications(recipient_id);

CREATE INDEX idx_audit_logs_actor
ON public.audit_logs(actor_id);

-- =========================================
-- SECURITY HELPER FUNCTIONS
-- =========================================

CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS TEXT
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT p.role
    FROM public.profiles AS p
    WHERE p.id = (SELECT auth.uid())
$$;

CREATE OR REPLACE FUNCTION public.is_staff()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT COALESCE(
        public.current_user_role() IN (
            'teacher',
            'class_president',
            'academic_monitor',
            'labor_monitor'
        ),
        FALSE
    )
$$;

CREATE OR REPLACE FUNCTION public.is_group_leader(target_group UUID)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.group_members AS gm
        WHERE gm.student_id = (SELECT auth.uid())
          AND gm.group_id = target_group
          AND gm.is_leader = TRUE
    )
$$;

CREATE OR REPLACE FUNCTION public.is_member_of_group(
    target_group UUID,
    target_student UUID
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.group_members AS gm
        WHERE gm.group_id = target_group
          AND gm.student_id = target_student
    )
$$;

-- =========================================
-- ENABLE RLS
-- =========================================

ALTER TABLE public.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.score_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chores ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- =========================================
-- GROUPS POLICIES
-- =========================================

CREATE POLICY "groups_read_authenticated"
ON public.groups
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "groups_staff_manage"
ON public.groups
FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- =========================================
-- PROFILES POLICIES
-- =========================================

CREATE POLICY "profiles_read_authenticated"
ON public.profiles
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "profiles_staff_manage"
ON public.profiles
FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- Students cannot change their own role or username
-- through direct table updates.
-- Password changes must use Supabase Auth.

-- =========================================
-- GROUP MEMBERS POLICIES
-- =========================================

CREATE POLICY "members_read_authenticated"
ON public.group_members
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "members_staff_manage"
ON public.group_members
FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- Group leaders will manage membership
-- through a separately secured server function.

-- =========================================
-- SCORE POLICIES
-- =========================================

CREATE POLICY "scores_read_own_or_staff"
ON public.score_events
FOR SELECT TO authenticated
USING (
    student_id = (SELECT auth.uid())
    OR public.is_staff()
);

CREATE POLICY "scores_staff_manage"
ON public.score_events
FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- =========================================
-- CHORES POLICIES
-- =========================================

CREATE POLICY "chores_read_authenticated"
ON public.chores
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "chores_staff_manage"
ON public.chores
FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

CREATE POLICY "chores_leader_manage_own_group"
ON public.chores
FOR ALL TO authenticated
USING (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
)
WITH CHECK (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
    AND (
        assigned_to IS NULL
        OR public.is_member_of_group(group_id, assigned_to)
    )
);

-- =========================================
-- NOTIFICATION POLICIES
-- =========================================

CREATE POLICY "notifications_read_own_or_staff"
ON public.notifications
FOR SELECT TO authenticated
USING (
    recipient_id = (SELECT auth.uid())
    OR public.is_staff()
);

CREATE POLICY "notifications_staff_insert"
ON public.notifications
FOR INSERT TO authenticated
WITH CHECK (public.is_staff());

-- Password-change notifications will be created
-- by a trusted backend function, not by the browser.

-- =========================================
-- AUDIT LOG POLICIES
-- =========================================

CREATE POLICY "audit_staff_read"
ON public.audit_logs
FOR SELECT TO authenticated
USING (public.is_staff());

CREATE POLICY "audit_insert_own"
ON public.audit_logs
FOR INSERT TO authenticated
WITH CHECK (actor_id = (SELECT auth.uid()));

-- =========================================
-- END OF INITIAL SCHEMA
-- =========================================
