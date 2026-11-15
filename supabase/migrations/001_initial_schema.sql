
-- =========================================
-- LOP 9/2 - INITIAL DATABASE SCHEMA
-- =========================================

-- 1. GROUPS
CREATE TABLE public.groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.groups (name)
VALUES ('Tổ 1'), ('Tổ 2'), ('Tổ 3'), ('Tổ 4');

-- 2. USER PROFILES
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
            'labor_monitor'
        )),
    must_change_password BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. GROUP MEMBERS
CREATE TABLE public.group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    is_leader BOOLEAN DEFAULT FALSE,
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
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. CHORES / DUTY SCHEDULE
CREATE TABLE public.chores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES public.groups(id),
    assigned_to UUID REFERENCES public.profiles(id),
    duty_date DATE NOT NULL,
    area TEXT NOT NULL,
    task TEXT NOT NULL,
    is_exempt BOOLEAN DEFAULT FALSE,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. NOTIFICATIONS
CREATE TABLE public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_id UUID REFERENCES public.profiles(id),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. AUDIT LOGS
CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.profiles(id),
    action TEXT NOT NULL,
    details JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =========================================
-- SECURITY FUNCTIONS
-- =========================================

CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS TEXT
LANGUAGE SQL
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
    SELECT role
    FROM public.profiles
    WHERE id = (SELECT auth.uid())
$$;

CREATE OR REPLACE FUNCTION public.is_group_leader(target_group UUID)
RETURNS BOOLEAN
LANGUAGE SQL
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.group_members
        WHERE student_id = (SELECT auth.uid())
          AND group_id = target_group
          AND is_leader = TRUE
    )
$$;

CREATE OR REPLACE FUNCTION public.is_staff()
RETURNS BOOLEAN
LANGUAGE SQL
SECURITY DEFINER
SET search_path = ''
STABLE
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

-- =========================================
-- ENABLE ROW LEVEL SECURITY
-- =========================================

ALTER TABLE public.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.score_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chores ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- GROUPS
CREATE POLICY "Authenticated users can view groups"
ON public.groups FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Staff manage groups"
ON public.groups FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- PROFILES
CREATE POLICY "Authenticated users can view profiles"
ON public.profiles FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Staff manage profiles"
ON public.profiles FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- GROUP MEMBERS
CREATE POLICY "Authenticated users view group members"
ON public.group_members FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Staff manage group members"
ON public.group_members FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

CREATE POLICY "Group leaders manage their own group"
ON public.group_members FOR ALL TO authenticated
USING (public.is_group_leader(group_id))
WITH CHECK (public.is_group_leader(group_id));

-- SCORE EVENTS
CREATE POLICY "Students view their own scores and staff view all"
ON public.score_events FOR SELECT TO authenticated
USING (
    student_id = (SELECT auth.uid())
    OR public.is_staff()
);

CREATE POLICY "Staff manage score events"
ON public.score_events FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

-- CHORES
CREATE POLICY "Authenticated users view chores"
ON public.chores FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Staff manage chores"
ON public.chores FOR ALL TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

CREATE POLICY "Group leaders manage their group chores"
ON public.chores FOR ALL TO authenticated
USING (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
)
WITH CHECK (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
);

-- NOTIFICATIONS
CREATE POLICY "Users view their own notifications"
ON public.notifications FOR SELECT TO authenticated
USING (
    recipient_id = (SELECT auth.uid())
    OR public.is_staff()
);

CREATE POLICY "Users mark their own notifications as read"
ON public.notifications FOR UPDATE TO authenticated
USING (recipient_id = (SELECT auth.uid()))
WITH CHECK (recipient_id = (SELECT auth.uid()));

-- AUDIT LOGS
CREATE POLICY "Staff view audit logs"
ON public.audit_logs FOR SELECT TO authenticated
USING (public.is_staff());

CREATE POLICY "Authenticated users create audit logs"
ON public.audit_logs FOR INSERT TO authenticated
WITH CHECK (actor_id = (SELECT auth.uid()));

-- =========================================
-- END
-- =========================================

