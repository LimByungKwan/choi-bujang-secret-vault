-- 원인: issue_device_approval_challenge 함수의 p_challenge 정규식 반복 상한이
-- PostgreSQL 정규식 반복 상한인 255를 넘어서, 함수를 호출할 때마다
-- 오류 2201B(invalid_regular_expression)가 났다.
-- 수정: 반복 상한을 255로 낮춘 같은 함수 정의로 교체한다. 다른 동작은 그대로다.
BEGIN;

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
      OR p_challenge !~ '^[A-Za-z0-9_-]{20,255}$'
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

COMMIT;
