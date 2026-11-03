BEGIN;

CREATE TABLE IF NOT EXISTS public.learning_note_restore_audit (
  operation_id uuid PRIMARY KEY,
  actor_id uuid NOT NULL,
  note_id uuid,
  backup_ref text,
  outcome text NOT NULL CHECK (
    outcome IN ('restored', 'no_change', 'conflict', 'not_owned', 'failed', 'rejected')
  ),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (backup_ref IS NULL OR backup_ref ~ '^nb1_[0-9a-f]{64}$')
);

ALTER TABLE public.learning_note_restore_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE public.learning_note_restore_audit
  FROM PUBLIC, anon, authenticated;
GRANT INSERT ON TABLE public.learning_note_restore_audit TO service_role;

GRANT SELECT, INSERT, UPDATE ON TABLE public.learning_notes TO service_role;

CREATE OR REPLACE FUNCTION public.restore_learning_note(
  p_operation_id uuid,
  p_note_id uuid,
  p_owner_id uuid,
  p_title text,
  p_content text,
  p_expected_state text,
  p_expected_title text,
  p_expected_content text,
  p_backup_ref text
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  current_owner_id uuid;
  current_title text;
  current_content text;
  affected_id uuid;
  restore_outcome text;
BEGIN
  IF p_operation_id IS NULL
      OR p_note_id IS NULL
      OR p_owner_id IS NULL
      OR p_title IS NULL
      OR p_content IS NULL
      OR p_backup_ref IS NULL
      OR p_backup_ref !~ '^nb1_[0-9a-f]{64}$'
      OR p_expected_state IS NULL
      OR p_expected_state NOT IN ('absent', 'present')
      OR (p_expected_state = 'absent'
        AND (p_expected_title IS NOT NULL OR p_expected_content IS NOT NULL))
      OR (p_expected_state = 'present'
        AND (p_expected_title IS NULL OR p_expected_content IS NULL)) THEN
    IF p_operation_id IS NOT NULL AND p_owner_id IS NOT NULL THEN
      INSERT INTO public.learning_note_restore_audit (
        operation_id, actor_id, note_id, backup_ref, outcome
      ) VALUES (
        p_operation_id, p_owner_id, p_note_id, p_backup_ref, 'rejected'
      ) ON CONFLICT (operation_id) DO NOTHING;
    END IF;
    RETURN 'rejected';
  END IF;

  BEGIN
    IF p_expected_state = 'absent' THEN
      INSERT INTO public.learning_notes (id, owner_id, title, content)
      VALUES (p_note_id, p_owner_id, p_title, p_content)
      ON CONFLICT (id) DO NOTHING
      RETURNING id INTO affected_id;

      IF affected_id IS NOT NULL THEN
        restore_outcome := 'restored';
      ELSE
        SELECT owner_id, title, content
          INTO current_owner_id, current_title, current_content
          FROM public.learning_notes
          WHERE id = p_note_id
          FOR UPDATE;

        IF NOT FOUND THEN
          restore_outcome := 'conflict';
        ELSIF current_owner_id = p_owner_id
            AND current_title = p_title
            AND current_content = p_content THEN
          restore_outcome := 'no_change';
        ELSE
          restore_outcome := 'conflict';
        END IF;
      END IF;
    ELSE
      SELECT owner_id, title, content
        INTO current_owner_id, current_title, current_content
        FROM public.learning_notes
        WHERE id = p_note_id
        FOR UPDATE;

      IF NOT FOUND THEN
        restore_outcome := 'conflict';
      ELSIF current_owner_id IS DISTINCT FROM p_owner_id THEN
        restore_outcome := 'not_owned';
      ELSIF current_title = p_title AND current_content = p_content THEN
        restore_outcome := 'no_change';
      ELSIF current_title IS DISTINCT FROM p_expected_title
          OR current_content IS DISTINCT FROM p_expected_content THEN
        restore_outcome := 'conflict';
      ELSE
        UPDATE public.learning_notes
          SET title = p_title, content = p_content
          WHERE id = p_note_id
            AND owner_id = p_owner_id
            AND title IS NOT DISTINCT FROM p_expected_title
            AND content IS NOT DISTINCT FROM p_expected_content
          RETURNING id INTO affected_id;

        restore_outcome := CASE
          WHEN affected_id IS NULL THEN 'conflict'
          ELSE 'restored'
        END;
      END IF;
    END IF;

    INSERT INTO public.learning_note_restore_audit (
      operation_id, actor_id, note_id, backup_ref, outcome
    ) VALUES (
      p_operation_id, p_owner_id, p_note_id, p_backup_ref, restore_outcome
    );
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO public.learning_note_restore_audit (
      operation_id, actor_id, note_id, backup_ref, outcome
    ) VALUES (
      p_operation_id, p_owner_id, p_note_id, p_backup_ref, 'failed'
    ) ON CONFLICT (operation_id) DO NOTHING;
    RETURN 'failed';
  END;

  RETURN restore_outcome;
END;
$function$;

REVOKE ALL PRIVILEGES ON FUNCTION public.restore_learning_note(
  uuid, uuid, uuid, text, text, text, text, text, text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.restore_learning_note(
  uuid, uuid, uuid, text, text, text, text, text, text
) TO service_role;

COMMIT;
