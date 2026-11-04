BEGIN;

CREATE TABLE public.device_approval_credentials (
  credential_id text PRIMARY KEY,
  owner_id uuid NOT NULL,
  public_key text NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_by uuid,
  approved_at timestamptz,
  revoked_at timestamptz
);

CREATE INDEX device_approval_credentials_owner_status
  ON public.device_approval_credentials (owner_id, status);

CREATE TABLE public.device_approval_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('registration', 'status', 'notes')),
  challenge text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  http_method text,
  canonical_target text,
  body_sha256 text,
  body_present boolean,
  CHECK (
    (purpose = 'notes'
      AND http_method IS NOT NULL
      AND canonical_target IS NOT NULL
      AND body_present IS NOT NULL
      AND (
        (body_present AND body_sha256 IS NOT NULL AND body_sha256 ~ '^[0-9a-f]{64}$')
        OR (NOT body_present AND body_sha256 IS NULL)
      ))
    OR
    (purpose <> 'notes'
      AND http_method IS NULL
      AND canonical_target IS NULL
      AND body_sha256 IS NULL
      AND body_present IS NULL)
  )
);

ALTER TABLE public.device_approval_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_approval_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE public.device_approval_credentials,
  public.device_approval_challenges FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.device_approval_credentials TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.device_approval_challenges TO service_role;

CREATE OR REPLACE FUNCTION public.issue_device_approval_challenge(
  p_owner_id uuid,
  p_purpose text,
  p_challenge text,
  p_expires_at timestamptz,
  p_http_method text,
  p_canonical_target text,
  p_body_sha256 text,
  p_body_present boolean
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  issued_id uuid;
BEGIN
  IF p_owner_id IS NULL
      OR p_purpose IS NULL
      OR p_purpose NOT IN ('registration', 'status', 'notes')
      OR p_challenge IS NULL
      OR p_challenge !~ '^[A-Za-z0-9_-]{20,256}$'
      OR p_expires_at IS NULL
      OR p_expires_at <= now()
      OR p_expires_at > now() + interval '10 minutes'
      OR (p_purpose = 'notes' AND (
        p_http_method IS NULL
        OR p_http_method NOT IN ('GET', 'POST', 'PUT', 'DELETE')
        OR p_canonical_target IS NULL
        OR p_canonical_target !~ '^/api/notes(/([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|restore))?([?][A-Za-z0-9._~%=&-]*)?$'
        OR p_body_present IS NULL
        OR (p_body_present AND (
          p_body_sha256 IS NULL OR p_body_sha256 !~ '^[0-9a-f]{64}$'
        ))
        OR (NOT p_body_present AND p_body_sha256 IS NOT NULL)
      ))
      OR (p_purpose <> 'notes' AND (
        p_http_method IS NOT NULL
        OR p_canonical_target IS NOT NULL
        OR p_body_sha256 IS NOT NULL
        OR p_body_present IS NOT NULL
      )) THEN
    RETURN NULL;
  END IF;

  DELETE FROM public.device_approval_challenges
    WHERE consumed_at IS NOT NULL OR expires_at <= now();

  INSERT INTO public.device_approval_challenges (
    owner_id, purpose, challenge, expires_at,
    http_method, canonical_target, body_sha256, body_present
  ) VALUES (
    p_owner_id, p_purpose, p_challenge, p_expires_at,
    p_http_method, p_canonical_target, p_body_sha256, p_body_present
  ) RETURNING id INTO issued_id;
  RETURN issued_id;
END;
$function$;

CREATE OR REPLACE FUNCTION public.complete_device_registration(
  p_challenge_id uuid,
  p_owner_id uuid,
  p_challenge text,
  p_credential_id text,
  p_public_key text,
  p_sign_count bigint,
  p_transports text[]
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  consumed_id uuid;
BEGIN
  UPDATE public.device_approval_challenges
    SET consumed_at = now()
    WHERE id = p_challenge_id
      AND owner_id = p_owner_id
      AND purpose = 'registration'
      AND challenge = p_challenge
      AND consumed_at IS NULL
      AND expires_at > now()
    RETURNING id INTO consumed_id;
  IF consumed_id IS NULL THEN RETURN 'invalid_challenge'; END IF;

  INSERT INTO public.device_approval_credentials (
    credential_id, owner_id, public_key, sign_count, transports
  ) VALUES (
    p_credential_id, p_owner_id, p_public_key, p_sign_count, p_transports
  ) ON CONFLICT (credential_id) DO NOTHING;
  IF NOT FOUND THEN RETURN 'credential_conflict'; END IF;
  RETURN 'pending';
END;
$function$;

CREATE OR REPLACE FUNCTION public.consume_device_assertion(
  p_challenge_id uuid,
  p_owner_id uuid,
  p_challenge text,
  p_credential_id text,
  p_sign_count bigint,
  p_http_method text,
  p_canonical_target text,
  p_body_sha256 text,
  p_body_present boolean
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  challenge_row public.device_approval_challenges%ROWTYPE;
  current_status text;
  current_count bigint;
BEGIN
  SELECT * INTO challenge_row
    FROM public.device_approval_challenges
    WHERE id = p_challenge_id
      AND owner_id = p_owner_id
      AND purpose IN ('status', 'notes')
      AND challenge = p_challenge
      AND consumed_at IS NULL
      AND expires_at > now()
      AND (
        (purpose = 'notes'
          AND http_method IS NOT DISTINCT FROM p_http_method
          AND canonical_target IS NOT DISTINCT FROM p_canonical_target
          AND body_sha256 IS NOT DISTINCT FROM p_body_sha256
          AND body_present IS NOT DISTINCT FROM p_body_present)
        OR
        (purpose IN ('status', 'registration')
          AND p_http_method IS NULL
          AND p_canonical_target IS NULL
          AND p_body_sha256 IS NULL
          AND p_body_present IS NULL)
      )
    FOR UPDATE;
  IF NOT FOUND THEN RETURN 'invalid_challenge'; END IF;

  UPDATE public.device_approval_challenges
    SET consumed_at = now()
    WHERE id = p_challenge_id;

  SELECT status, sign_count INTO current_status, current_count
    FROM public.device_approval_credentials
    WHERE credential_id = p_credential_id AND owner_id = p_owner_id
    FOR UPDATE;
  IF NOT FOUND THEN RETURN 'unknown'; END IF;
  IF p_sign_count < current_count THEN RETURN 'invalid_counter'; END IF;

  UPDATE public.device_approval_credentials
    SET sign_count = p_sign_count
    WHERE credential_id = p_credential_id AND owner_id = p_owner_id;
  RETURN current_status;
END;
$function$;

CREATE OR REPLACE FUNCTION public.decide_device_approval(
  p_credential_id text,
  p_owner_id uuid,
  p_admin_id uuid,
  p_action text
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  current_status text;
BEGIN
  IF p_action NOT IN ('approve', 'reject', 'revoke') THEN RETURN 'invalid_action'; END IF;
  SELECT status INTO current_status
    FROM public.device_approval_credentials
    WHERE credential_id = p_credential_id AND owner_id = p_owner_id
    FOR UPDATE;
  IF NOT FOUND THEN RETURN 'not_found'; END IF;

  IF p_action IN ('approve', 'reject') AND current_status = 'pending' THEN
    UPDATE public.device_approval_credentials
      SET status = CASE p_action WHEN 'approve' THEN 'approved' ELSE 'rejected' END,
          approved_by = CASE p_action WHEN 'approve' THEN p_admin_id ELSE NULL END,
          approved_at = CASE p_action WHEN 'approve' THEN now() ELSE NULL END
      WHERE credential_id = p_credential_id AND owner_id = p_owner_id;
    RETURN CASE p_action WHEN 'approve' THEN 'approved' ELSE 'rejected' END;
  END IF;

  IF p_action = 'revoke' AND current_status = 'approved' THEN
    UPDATE public.device_approval_credentials
      SET status = 'revoked', revoked_at = now()
      WHERE credential_id = p_credential_id AND owner_id = p_owner_id;
    RETURN 'revoked';
  END IF;
  RETURN 'conflict';
END;
$function$;

REVOKE ALL PRIVILEGES ON FUNCTION public.complete_device_registration(
  uuid, uuid, text, text, text, bigint, text[]
) FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON FUNCTION public.issue_device_approval_challenge(
  uuid, text, text, timestamptz, text, text, text, boolean
) FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON FUNCTION public.consume_device_assertion(
  uuid, uuid, text, text, bigint, text, text, text, boolean
) FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON FUNCTION public.decide_device_approval(
  text, uuid, uuid, text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.complete_device_registration(
  uuid, uuid, text, text, text, bigint, text[]
) TO service_role;
GRANT EXECUTE ON FUNCTION public.issue_device_approval_challenge(
  uuid, text, text, timestamptz, text, text, text, boolean
) TO service_role;
GRANT EXECUTE ON FUNCTION public.consume_device_assertion(
  uuid, uuid, text, text, bigint, text, text, text, boolean
) TO service_role;
GRANT EXECUTE ON FUNCTION public.decide_device_approval(
  text, uuid, uuid, text
) TO service_role;

COMMIT;
