BEGIN;
CREATE OR REPLACE FUNCTION public.learning_note_restore_audit_summary()
RETURNS TABLE (outcome text, outcome_count bigint, latest_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT a.outcome, count(*)::bigint, max(a.created_at)
  FROM public.learning_note_restore_audit AS a
  GROUP BY a.outcome
$$;
REVOKE ALL PRIVILEGES ON FUNCTION public.learning_note_restore_audit_summary() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.learning_note_restore_audit_summary() TO service_role;
COMMIT;
