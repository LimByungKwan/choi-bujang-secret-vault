BEGIN;

CREATE TABLE IF NOT EXISTS public.learning_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid,
  title text NOT NULL,
  content text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.learning_notes ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE public.learning_notes FROM PUBLIC, anon, authenticated;

INSERT INTO public.learning_notes (id, owner_id, title, content)
VALUES
  ('20000000-0000-4000-8000-000000000001', NULL, '과제', '실습용 가상 과제 기록'),
  ('20000000-0000-4000-8000-000000000002', NULL, '포트폴리오', '실습용 가상 포트폴리오 기록'),
  ('20000000-0000-4000-8000-000000000003', NULL, '아침 리추얼', '실습용 가상 리추얼 기록'),
  ('20000000-0000-4000-8000-000000000004', NULL, '훈련 행정 자료', '실습용 가상 행정 기록')
ON CONFLICT (id) DO NOTHING;

COMMIT;