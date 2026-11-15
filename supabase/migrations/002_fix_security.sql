
-- =========================================
-- LOP 9/2 - SECURITY PATCH V2
-- Migration: 002_fix_security.sql
-- =========================================

-- 1. REMOVE OLD POLICIES
DO $$
DECLARE
    p RECORD;
BEGIN
    FOR p IN
        SELECT schemaname, tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename IN (
              'groups',
              'profiles',
              'group_members',
              'score_events',
              'chores',
              'notifications',
              'audit_logs'
          )
    LOOP
        EXECUTE format(
            'DROP POLICY IF EXISTS %I ON %I.%I',
            p.policyname,
            p.schemaname,
            p.tablename
        );
    END LOOP;
END $$;

-- 2. REVOKE DEFAULT TABLE PRIVILEGES
REVOKE ALL ON TABLE
    public.groups,
    public.profiles,
    public.group_members,
    public.score_events,
    public.chores,
    public.notifications,
    public.audit_logs
FROM anon;

GRANT SELECT ON TABLE
    public.groups,
    public.profiles,
    public.group_members,
    public.score_events,
    public.chores,
    public.notifications
TO authenticated;

GRANT INSERT, UPDATE, DELETE ON TABLE
    public.groups,
    public.profiles,
    public.group_members,
    public.score_events,
    public.chores,
    public.notifications,
    public.audit_logs
TO authenticated;

-- 3. SAFE HELPER FUNCTIONS
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT COALESCE(
        public.current_user_role() = 'teacher',
        FALSE
    )
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

-- 4. GROUPS
CREATE POLICY "groups_authenticated_read"
ON public.groups
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "groups_teacher_manage"
ON public.groups
FOR ALL TO authenticated
USING (public.is_teacher())
WITH CHECK (public.is_teacher());

-- 5. PROFILES
CREATE POLICY "profiles_authenticated_read"
ON public.profiles
FOR SELECT TO authenticated
USING (true);

-- Only teacher can manage profiles.
-- Students cannot update their own role.
CREATE POLICY "profiles_teacher_manage"
ON public.profiles
FOR ALL TO authenticated
USING (public.is_teacher())
WITH CHECK (public.is_teacher());

-- 6. GROUP MEMBERS
CREATE POLICY "members_authenticated_read"
ON public.group_members
FOR SELECT TO authenticated
USING (true);

-- Only teacher can modify group membership or leader status.
CREATE POLICY "members_teacher_manage"
ON public.group_members
FOR ALL TO authenticated
USING (public.is_teacher())
WITH CHECK (public.is_teacher());

-- 7. SCORE EVENTS
CREATE POLICY "scores_read_own_or_staff"
ON public.score_events
FOR SELECT TO authenticated
USING (
    student_id = (SELECT auth.uid())
    OR public.is_staff()
);

CREATE POLICY "scores_staff_insert"
ON public.score_events
FOR INSERT TO authenticated
WITH CHECK (
    public.is_staff()
    AND created_by = (SELECT auth.uid())
);

CREATE POLICY "scores_teacher_update"
ON public.score_events
FOR UPDATE TO authenticated
USING (public.is_teacher())
WITH CHECK (public.is_teacher());

CREATE POLICY "scores_teacher_delete"
ON public.score_events
FOR DELETE TO authenticated
USING (public.is_teacher());

-- 8. CHORES
CREATE POLICY "chores_authenticated_read"
ON public.chores
FOR SELECT TO authenticated
USING (true);

CREATE POLICY "chores_staff_insert"
ON public.chores
FOR INSERT TO authenticated
WITH CHECK (public.is_staff());

CREATE POLICY "chores_staff_update"
ON public.chores
FOR UPDATE TO authenticated
USING (public.is_staff())
WITH CHECK (public.is_staff());

CREATE POLICY "chores_staff_delete"
ON public.chores
FOR DELETE TO authenticated
USING (public.is_staff());

-- Group leaders may update completion status only.
-- They cannot change assignments, group, date or task.
CREATE POLICY "chores_leader_update_completion"
ON public.chores
FOR UPDATE TO authenticated
USING (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
)
WITH CHECK (
    group_id IS NOT NULL
    AND public.is_group_leader(group_id)
);

-- 9. NOTIFICATIONS
CREATE POLICY "notifications_read_own"
ON public.notifications
FOR SELECT TO authenticated
USING (recipient_id = (SELECT auth.uid()));

CREATE POLICY "notifications_teacher_insert"
ON public.notifications
FOR INSERT TO authenticated
WITH CHECK (public.is_teacher());

CREATE POLICY "notifications_teacher_update"
ON public.notifications
FOR UPDATE TO authenticated
USING (public.is_teacher())
WITH CHECK (public.is_teacher());

CREATE POLICY "notifications_teacher_delete"
ON public.notifications
FOR DELETE TO authenticated
USING (public.is_teacher());

-- 10. AUDIT LOGS
CREATE POLICY "audit_teacher_read"
ON public.audit_logs
FOR SELECT TO authenticated
USING (public.is_teacher());

-- Browser users cannot insert or modify audit logs.
-- Trusted backend/service role should write audit logs.

-- 11. LOCK DOWN FUNCTION EXECUTION
REVOKE ALL ON FUNCTION public.current_user_role() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_staff() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_group_leader(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_member_of_group(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_teacher() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.current_user_role() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_staff() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_group_leader(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_member_of_group(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_teacher() TO authenticated;

-- =========================================
-- END SECURITY PATCH V2
-- =========================================

