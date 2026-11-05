// 보너스 xdr-05 제작 3 · 판단 모듈 (privilege)
// 바깥 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 네트워크를 쓰지 않습니다.
// 아래 PATTERNS 는 xdr/privilege/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'admin_group_addition',
    condition: 'data.group 이 정확히 "administrators" 이다. 설명에 관리자 그룹이라는 말이 있어도 data.group 값이 다르거나 없으면 해당하지 않는다.',
    evidence: 'T1078 은 탈취한 정상 계정으로 더 높은 권한을 얻는 행위를 다루며, 계정이 관리자 그룹에 들어가는 것은 그 권한 변화가 드러나는 신호다.',
  }),
  Object.freeze({
    name: 'admin_added_then_command',
    condition: 'data.group 이 정확히 "administrators" 이고 설명에 명령 실행이 함께 있거나, 설명이 방금 관리자가 된 계정의 명령 실행을 말한다. "이어서 명령은 없습니다" 처럼 명령을 부정하면 해당하지 않는다.',
    evidence: 'T1078 은 정상 계정으로 얻은 높은 권한의 악용을 다루며, 관리자가 된 직후의 명령 실행은 얻은 권한을 실제로 쓴 형태다.',
  }),
  Object.freeze({
    name: 'unfamiliar_source_privilege_use',
    condition: '설명이 처음 보는 주소("처음 보는 주소", "요청 주소는 처음")를 말하고, 관리자 명령 실행이나 세션의 관리자 권한 전환이 함께 있다.',
    evidence: 'T1078 의 탐지 지침은 평소와 맞지 않는 위치의 계정 활동을 살피며, T1068 은 낮은 권한에서 높은 권한으로 넘어가는 상승을 다루므로 처음 보는 주소의 권한 전환은 두 기법의 뚜렷한 신호다.',
  }),
  Object.freeze({
    name: 'borrowed_account_admin_command',
    condition: '설명이 다른 계정의 권한으로 관리자 명령을 실행했다고 말한다.',
    evidence: 'T1078 은 기존 계정의 자격 증명을 얻어 악용하는 기법이므로, 자기 계정이 아닌 다른 계정의 권한으로 실행한 관리자 명령은 그 직접적인 형태다.',
  }),
  Object.freeze({
    name: 'multi_account_admin_addition',
    condition: 'data.group 이 정확히 "administrators" 이고 data.count 가 2 이상이며, 설명이 같은 주소에서 여러 계정이 추가됐다고 말한다.',
    evidence: 'T1078 은 여러 기존 계정의 악용과 높은 권한 획득을 다루며, 한 주소에서 여러 계정이 관리자가 되는 것은 개별 업무 변경으로 보기 어려운 형태다.',
  }),
  Object.freeze({
    name: 'admin_readdition_after_removal',
    condition: 'data.group 이 정확히 "administrators" 이고, 설명이 관리자 그룹에서 빠진 계정이 곧바로 다시 들어왔다고 말한다.',
    evidence: 'T1078 은 정상 계정을 통한 접근 유지(Persistence)와 권한 상승을 함께 다루며, 회수된 관리자 권한이 곧바로 되살아나는 것은 그 권한을 유지하려는 형태다.',
  }),
  Object.freeze({
    name: 'off_hours_privilege_use',
    condition: '설명에 "수업 시간 밖" 또는 "업무처럼 보이지 않는 시각" 이 있고, 관리자 명령 실행이나 관리자 그룹 추가가 함께 있다. timestamp 로 계산하지 않는다.',
    evidence: 'T1078 의 탐지 지침은 평소와 맞지 않는 시각의 계정 활동을 살피므로, 업무 시간 밖의 관리자 권한 사용은 계정 도용을 의심할 근거다.',
  }),
  Object.freeze({
    name: 'unverified_privilege_review',
    condition: 'rule.mitre 에 T1068 또는 T1078 이 있으나 위 패턴이 성립하지 않는다. 취소, 실패, "없습니다", 평소 주소, 관리자가 아닌 그룹처럼 뚜렷한 신호가 없는 경우다. 차단하지 않고 알림으로만 남긴다.',
    evidence: 'T1068 은 성공한 권한 상승을, T1078 은 계정의 악용을 다루므로, 취소·실패했거나 오용이 드러나지 않은 흔적은 두 기법으로 확정할 수 없는 검토 대상이다.',
  }),
]);

const PATTERN_NAMES = new Set(PATTERNS.map((p) => p.name));

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MIN_BLOCK_LEVEL = 10;
const MIN_REVIEW_LEVEL = 5;
const MAX_TEXT = 8192;

const ADMIN_GROUP = 'administrators';
const PRIVILEGE_TECHNIQUES = ['T1068', 'T1078'];
const NEGATION_TEXT = /취소|실패|없습니다|아닙니다/u;
const COMMAND_RUN_TEXT = /명령[^.]*실행/u;
const ADMIN_COMMAND_RUN_TEXT = /(?:관리자|권한)\s*명령[^.]*실행/u;
const JUST_PROMOTED_TEXT = /방금 관리자가 된/u;
const UNFAMILIAR_SOURCE_TEXT = /처음 보는 주소|주소는 처음/u;
const SESSION_ELEVATION_TEXT = /세션[^.]*관리자 권한으로 바뀌/u;
const BORROWED_ACCOUNT_TEXT = /다른 계정의?\s*권한으로/u;
const MULTI_ACCOUNT_TEXT = /계정\s*\d+\s*개|여러 계정/u;
const READDED_TEXT = /빠진[^.]*다시/u;
const OFF_HOURS_TEXT = /수업 시간 밖|업무처럼 보이지 않는 시각/u;

function record(reason) {
  return { action: 'record', confidence: 0, reason };
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value) {
  return typeof value === 'string' && value.length <= MAX_TEXT ? value : '';
}

function reasonOf(matched) {
  return matched.filter((name) => PATTERN_NAMES.has(name)).join(', ');
}

// 부정 문구가 있으면 뚜렷한 패턴으로 치지 않습니다.
function clearPatterns(description, group, count) {
  if (NEGATION_TEXT.test(description)) return [];

  const isAdminGroup = group === ADMIN_GROUP;
  const commandRun = COMMAND_RUN_TEXT.test(description);
  const adminCommandRun = ADMIN_COMMAND_RUN_TEXT.test(description);

  const matched = [];
  if (isAdminGroup) matched.push('admin_group_addition');
  if ((isAdminGroup || JUST_PROMOTED_TEXT.test(description)) && commandRun) {
    matched.push('admin_added_then_command');
  }
  if (UNFAMILIAR_SOURCE_TEXT.test(description)
      && (adminCommandRun || SESSION_ELEVATION_TEXT.test(description))) {
    matched.push('unfamiliar_source_privilege_use');
  }
  if (BORROWED_ACCOUNT_TEXT.test(description) && adminCommandRun) {
    matched.push('borrowed_account_admin_command');
  }
  if (isAdminGroup && Number.isFinite(count) && count >= 2 && MULTI_ACCOUNT_TEXT.test(description)) {
    matched.push('multi_account_admin_addition');
  }
  if (isAdminGroup && READDED_TEXT.test(description)) {
    matched.push('admin_readdition_after_removal');
  }
  if (OFF_HOURS_TEXT.test(description) && (adminCommandRun || isAdminGroup)) {
    matched.push('off_hours_privilege_use');
  }
  return matched;
}

function evaluate(alert) {
  if (!isRecord(alert) || !isRecord(alert.rule) || !isRecord(alert.data)
      || !Number.isFinite(alert.rule.level)) {
    return record('invalid_input');
  }

  const level = alert.rule.level;
  const description = boundedText(alert.rule.description);
  const mitre = Array.isArray(alert.rule.mitre) ? alert.rule.mitre : [];
  const matched = clearPatterns(description, alert.data.group, Number(alert.data.count));

  if (matched.length > 0) {
    // 뚜렷한 패턴 + 경보 수준 10 이상이면 공격으로 보고, 맞는 패턴이 더 있으면 확신도를 높입니다.
    const base = level >= MIN_BLOCK_LEVEL
      ? BLOCK_AT + (level - MIN_BLOCK_LEVEL) * 0.01
      : 0.6 + clamp(level, 0, 9) * 0.02;
    const confidence = round2(clamp(
      base + (matched.length - 1) * 0.03,
      0,
      level >= MIN_BLOCK_LEVEL ? 0.99 : BLOCK_AT - 0.01,
    ));
    return {
      action: confidence >= BLOCK_AT ? 'block' : 'alert',
      confidence,
      reason: reasonOf(matched),
    };
  }

  const hasTechnique = PRIVILEGE_TECHNIQUES.some((id) => mitre.includes(id));
  if (hasTechnique && level >= MIN_REVIEW_LEVEL) {
    const confidence = round2(clamp(
      ALERT_AT + (clamp(level, MIN_REVIEW_LEVEL, 9) - MIN_REVIEW_LEVEL) * 0.05,
      ALERT_AT,
      0.7,
    ));
    return { action: 'alert', confidence, reason: reasonOf(['unverified_privilege_review']) };
  }

  return record('no_pattern_match');
}

export function decide(alert) {
  try {
    return evaluate(alert);
  } catch {
    return record('invalid_input');
  }
}
