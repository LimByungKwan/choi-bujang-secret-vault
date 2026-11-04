// These anonymous checks record observed HTTP responses; they do not decide whether a defense passed.
const SYNTHETIC_NOTE_ID = '00000000-0000-4000-8000-000000000000';

function hasNoteFields(value) {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(hasNoteFields);
  if (Object.hasOwn(value, 'title') || Object.hasOwn(value, 'content')) return true;
  if (Array.isArray(value.notes) && value.notes.length > 0) return true;
  return Object.values(value).some(hasNoteFields);
}

function check(expected, request) {
  return { attackId: request.attackId, expected, request };
}

function requests() {
  return [
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_note_read', method: 'GET', path: '/api/notes',
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_note_by_id', method: 'GET',
      path: `/api/notes/${SYNTHETIC_NOTE_ID}`,
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'forged_bearer_note_read', method: 'GET', path: '/api/notes',
      headers: { Authorization: 'Bearer invalid-synthetic-token' },
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'forged_approval_header', method: 'GET', path: '/api/notes',
      headers: { 'x-device-approved': 'true' },
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_note_update', method: 'PUT',
      path: `/api/notes/${SYNTHETIC_NOTE_ID}`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'synthetic note title', body: 'synthetic note body' }),
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_note_delete', method: 'DELETE',
      path: `/api/notes/${SYNTHETIC_NOTE_ID}`,
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_restore', method: 'POST', path: '/api/notes/restore',
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_device_admin_list', method: 'GET', path: '/api/device/admin',
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_device_admin_decide', method: 'POST',
      path: '/api/device/admin',
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    }),
    check('2xx가 아니고 메모 필드 없음', {
      attackId: 'anonymous_ops_summary', method: 'GET', path: '/api/ops/summary',
    }),
    check('405', {
      attackId: 'ops_summary_wrong_method', method: 'POST', path: '/api/ops/summary',
    }),
    check('403, Supabase 호출 전 거부', {
      attackId: 'cross_origin_login', method: 'POST', path: '/api/auth/login',
      headers: {
        Origin: 'https://attacker.invalid',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'synthetic@example.invalid',
        password: 'synthetic-password',
      }),
    }),
  ];
}

function requestIdFrom(response) {
  return response.headers.get('x-request-id')
    ?? response.headers.get('x-vercel-id')
    ?? '없음';
}

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 2) {
    throw new Error('2단계 이후의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const results = [];
  for (const { attackId, expected, request } of requests()) {
    const url = new URL(request.path, app);
    try {
      const response = await fetch(url, {
        method: request.method,
        headers: request.headers,
        ...(request.body === undefined ? {} : { body: request.body }),
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        credentials: 'omit',
      });
      let noteFields = false;
      try {
        noteFields = hasNoteFields(await response.json());
      } catch {
        noteFields = false;
      }
      results.push({
        attackId,
        expected,
        observed: `HTTP ${response.status} · 메모 필드 ${noteFields ? '있음' : '없음'} · 요청 ID ${requestIdFrom(response)} · ${new Date().toISOString()}`,
      });
    } catch {
      results.push({
        attackId,
        expected,
        observed: `미확인(요청 실패) · ${new Date().toISOString()}`,
      });
    }
  }
  return results;
}
