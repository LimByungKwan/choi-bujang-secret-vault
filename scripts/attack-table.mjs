import { pathToFileURL } from 'node:url';
import config from '../aleph.config.json' with { type: 'json' };
import { runAttackChecks } from '../src/attack-check.mjs';

const CHECK_DETAILS = {
  anonymous_note_read: { step: 3, kind: '금지', request: 'GET /api/notes' },
  anonymous_note_by_id: {
    step: 3, kind: '금지', request: 'GET /api/notes/{가상 UUID}',
  },
  forged_bearer_note_read: { step: 5, kind: '금지', request: 'GET /api/notes' },
  forged_approval_header: { step: 11, kind: '금지', request: 'GET /api/notes' },
  anonymous_note_update: {
    step: 3, kind: '금지', request: 'PUT /api/notes/{가상 UUID}',
  },
  anonymous_note_delete: {
    step: 3, kind: '금지', request: 'DELETE /api/notes/{가상 UUID}',
  },
  anonymous_restore: { step: 10, kind: '금지', request: 'POST /api/notes/restore' },
  anonymous_device_admin_list: { step: 11, kind: '금지', request: 'GET /api/device/admin' },
  anonymous_device_admin_decide: {
    step: 11, kind: '금지', request: 'POST /api/device/admin',
  },
  anonymous_ops_summary: { step: 12, kind: '금지', request: 'GET /api/ops/summary' },
  ops_summary_wrong_method: { step: 12, kind: '금지', request: 'POST /api/ops/summary' },
  cross_origin_login: { step: 5, kind: '금지', request: 'POST /api/auth/login' },
};

const COLUMNS = [
  '단계', '요청', '구분(정상/금지)', '기대 결과', '실제 결과',
  '요청 ID', '확인 시각', '방법', '상태',
];

function observedDetails(observed) {
  if (observed.startsWith('HTTP ')) {
    return { actual: observed, requestId: '', timestamp: '', status: '실측' };
  }
  return { actual: observed, requestId: '', timestamp: '', status: '미실행' };
}

function escapeCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\r', ' ').replaceAll('\n', ' ');
}

export function formatAttackTable(checks) {
  const lines = [
    `| ${COLUMNS.join(' | ')} |`,
    `| ${COLUMNS.map(() => '---').join(' | ')} |`,
  ];
  for (const result of checks) {
    const detail = CHECK_DETAILS[result.attackId];
    if (!detail) throw new Error('공격 점검 ID의 표 항목이 없습니다.');
    const observation = observedDetails(result.observed);
    const cells = [
      detail.step,
      detail.request,
      detail.kind,
      result.expected,
      observation.actual,
      observation.requestId,
      observation.timestamp,
      '자동',
      observation.status,
    ];
    lines.push(`| ${cells.map(escapeCell).join(' | ')} |`);
  }
  return `${lines.join('\n')}\n`;
}

if (process.argv[1]
    && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const checks = await runAttackChecks(config);
  process.stdout.write(formatAttackTable(checks));
}
