// 보너스 xdr-04 제작 3 · 판단 모듈 (persistence)
// 바깥 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 네트워크를 쓰지 않습니다.
// 아래 PATTERNS 는 xdr/persistence/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'temp_binary_autostart',
    condition: '서비스·예약 작업·시작 항목 같은 자동 실행 수단이 임시 폴더(Temp)의 실행 파일을 가리킨다.',
    evidence: 'T1543 과 T1053 은 재시작 뒤에도 악성 프로그램을 다시 실행시키는 지속 수단을 다루며, 임시 폴더는 정상 설치 프로그램이 상주 실행 파일을 두는 곳이 아니어서 뚜렷한 의심 근거다.',
  }),
  Object.freeze({
    name: 'unfamiliar_autostart_entry',
    condition: '처음 보거나 평소 목록에 없는 자동 실행 항목이 새로 나타났다.',
    evidence: 'T1543 과 T1053 의 탐지는 평소 기준과 다른 새 서비스·예약 작업을 찾는 데서 출발하므로, 기준 목록에 없는 항목은 지속 수단의 뚜렷한 후보다.',
  }),
  Object.freeze({
    name: 'unsigned_service_binary',
    condition: '자동 실행 항목의 실행 파일에 서명이 없다고 경보가 명시한다. 서명을 아직 모르거나 확인하지 못한 경우는 해당하지 않는다.',
    evidence: 'T1543.003 은 서비스를 만들거나 고쳐 악성 실행 파일을 돌리는 기법이며, 서명 없는 실행 파일로 등록되거나 바뀐 서비스는 정상 배포와 구분되는 근거다.',
  }),
  Object.freeze({
    name: 'unsigned_service_burst',
    condition: '서명 없는 자동 실행 등록이 같은 경보에서 2건 이상(data.count) 반복된다.',
    evidence: '한 번의 정상 설치와 달리 서명 없는 등록의 반복은 T1543 지속 수단을 원격에서 여러 번 시도한 형태다.',
  }),
  Object.freeze({
    name: 'multi_autostart_same_binary',
    condition: 'T1543 과 T1053 이 함께 표시되고 임시 폴더의 같은 실행 파일을 가리킨다.',
    evidence: '한 수단이 지워져도 남도록 지속 수단을 겹쳐 심는 것은 T1543 과 T1053 을 함께 쓰는 뚜렷한 형태다.',
  }),
  Object.freeze({
    name: 'unverified_autostart_review',
    condition: '자동 실행 흔적은 있으나 위 패턴이 성립하지 않고 rule.level 이 5 이상이거나, 수준이 낮아도 임시·시작 폴더의 실행 파일이 보인다. 차단하지 않고 알림으로만 남긴다.',
    evidence: 'T1543 과 T1053 은 정상 관리 작업에도 쓰이므로, 서명·친숙도 근거가 없는 항목은 지속 수단으로 확정할 수 없는 검토 대상이다.',
  }),
]);

const PATTERN_NAMES = new Set(PATTERNS.map((p) => p.name));

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MIN_BLOCK_LEVEL = 10;
const MIN_REVIEW_LEVEL = 5;
const MAX_TEXT = 8192;

const PERSISTENCE_TECHNIQUES = ['T1543', 'T1053'];
const EXECUTABLE = /\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js)$/u;
const TEMP_DIR = /\/te?mp\//u;
const STARTUP_DIR = /\/start menu\/programs\/startup\//u;
const AUTOSTART_TEXT = /서비스|예약 작업|시작 폴더|시작 프로그램|시작 항목/u;
const UNSIGNED_TEXT = /서명\s*(?:이|은|도)?\s*없/u;
const UNFAMILIAR_TEXT = /처음 보는|평소 목록에 없/u;
const NO_REGISTRATION_TEXT = /등록\s*(?:은|이)?\s*없/u;

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

function evaluate(alert) {
  if (!isRecord(alert) || !isRecord(alert.rule) || !isRecord(alert.data)
      || !Number.isFinite(alert.rule.level)) {
    return record('invalid_input');
  }

  const level = alert.rule.level;
  const description = boundedText(alert.rule.description);
  const mitre = Array.isArray(alert.rule.mitre) ? alert.rule.mitre : [];
  const path = boundedText(alert.data.path).replace(/\\/gu, '/').toLowerCase();
  const count = Number(alert.data.count);

  const hasTechnique = PERSISTENCE_TECHNIQUES.some((id) => mitre.includes(id));
  const hasBothTechniques = PERSISTENCE_TECHNIQUES.every((id) => mitre.includes(id));
  const isExecutable = EXECUTABLE.test(path);
  const inTemp = isExecutable && TEMP_DIR.test(path);
  const inStartup = isExecutable && STARTUP_DIR.test(path);
  const trace = hasTechnique || AUTOSTART_TEXT.test(description);
  // "서비스 등록은 없습니다" 처럼 등록을 부정하는 경보는 자동 실행 근거로 쓰지 않습니다.
  const autostart = trace && !NO_REGISTRATION_TEXT.test(description);
  const unsigned = autostart && UNSIGNED_TEXT.test(description);

  const matched = [];
  if (autostart && inTemp) matched.push('temp_binary_autostart');
  if (autostart && UNFAMILIAR_TEXT.test(description)) matched.push('unfamiliar_autostart_entry');
  if (unsigned) matched.push('unsigned_service_binary');
  if (unsigned && Number.isFinite(count) && count >= 2) matched.push('unsigned_service_burst');
  if (hasBothTechniques && autostart && inTemp) matched.push('multi_autostart_same_binary');

  if (matched.length > 0) {
    // 뚜렷한 패턴 + 경보 수준 10 이상이면 공격으로 보고, 맞는 패턴이 더 있으면 확신도를 높입니다.
    const base = level >= MIN_BLOCK_LEVEL
      ? BLOCK_AT + (level - MIN_BLOCK_LEVEL) * 0.01
      : 0.6 + clamp(level, 0, 9) * 0.02;
    const confidence = round2(clamp(base + (matched.length - 1) * 0.03, 0, 0.99));
    return {
      action: confidence >= BLOCK_AT ? 'block' : 'alert',
      confidence,
      reason: reasonOf(matched),
    };
  }

  const riskyPath = inTemp || inStartup;
  if ((trace && level >= MIN_REVIEW_LEVEL) || riskyPath) {
    const confidence = round2(clamp(
      ALERT_AT + (clamp(level, MIN_REVIEW_LEVEL, 9) - MIN_REVIEW_LEVEL) * 0.05,
      ALERT_AT,
      0.7,
    ));
    return { action: 'alert', confidence, reason: reasonOf(['unverified_autostart_review']) };
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
