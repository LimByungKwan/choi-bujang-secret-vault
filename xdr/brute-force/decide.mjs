// 보너스 xdr-01 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러옵니다. import 없음, 파일 읽기·쓰기 없음, 바깥 호출 없음.
// 아래 PATTERNS 는 xdr/brute-force/patterns.json 을 그대로 옮겨 적은 상수입니다.

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'same_source_failure_burst',
    technique: 'T1110.001',
    minLevel: 10,
    minFailures: 20,
  }),
  Object.freeze({
    name: 'password_spraying',
    technique: 'T1110.003',
    minLevel: 10,
    minAccounts: 5,
  }),
  Object.freeze({
    name: 'low_volume_failures',
    technique: 'T1110',
    minFailures: 2,
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

function toInt(value) {
  const n = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function round(n) {
  return Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
}

function pick(confidence, reason) {
  const c = round(confidence);
  const action = c >= BLOCK_AT ? 'block' : c >= ALERT_AT ? 'alert' : 'record';
  return { action, confidence: c, reason };
}

// 경보에서 판단에 쓰는 값만 꺼냅니다.
function features(alert) {
  const rule = alert && typeof alert.rule === 'object' && alert.rule ? alert.rule : {};
  const data = alert && typeof alert.data === 'object' && alert.data ? alert.data : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const level = Number.isFinite(rule.level) ? rule.level : 0;

  const accountList = typeof data.accounts === 'string'
    ? new Set(data.accounts.split(',').map((s) => s.trim()).filter(Boolean)).size
    : 0;
  const accountInText = toInt((description.match(/계정\s*(\d+)\s*개/) || [])[1]);
  const multiAccountText = /여러 계정|서로 다른 계정|계정 이름을 바꿔/.test(description);

  return {
    level,
    t1110: mitre.some((m) => m === 'T1110' || m.startsWith('T1110.')),
    failureText: /실패/.test(description),
    failures: toInt(data.count),
    accounts: Math.max(accountList, accountInText),
    multiAccountText,
    samePassword: /같은 비밀번호|같은 간격/.test(description),
    // "성공은 없습니다" 는 성공이 아닙니다.
    successAfter: /성공/.test(description) && !/성공(은|이)\s*없/.test(description),
  };
}

export function decide(alert) {
  const f = features(alert);
  const [burst, spray, low] = PATTERNS;

  // 로그인 실패 신호가 전혀 없으면 정상 이벤트로 기록만 합니다.
  if (!f.t1110 && !(f.failureText && f.failures >= low.minFailures)) {
    return pick(0.05, 'no_bruteforce_signal');
  }

  // 실패 뒤 성공했거나 규칙 수준이 낮으면 정상 사용자 실수와 겹칠 수 있어 차단까지 가지 않습니다.
  const cap = f.successAfter ? 0.6 : f.level < burst.minLevel ? 0.8 : 1;

  // password_spraying: 같은 주소가 여러 계정에 같은 비밀번호를 대입
  if (f.level >= spray.minLevel
      && (f.accounts >= spray.minAccounts || (f.multiAccountText && f.samePassword))) {
    const c = 0.86 + Math.min(0.1, f.accounts / 200) + (f.samePassword ? 0.02 : 0);
    return pick(Math.min(c, cap), spray.name);
  }

  // same_source_failure_burst: 짧은 시간 같은 주소의 실패 급증
  if (f.level >= burst.minLevel && f.failures >= burst.minFailures) {
    const c = 0.86 + Math.min(0.1, (f.failures - burst.minFailures) / 500)
      + (f.multiAccountText ? 0.02 : 0);
    return pick(Math.min(c, cap), burst.name);
  }

  // low_volume_failures: T1110 로 분류된 적은 실패 → 알림만
  if (f.failures >= low.minFailures || f.accounts >= 2 || f.t1110) {
    const c = 0.55 + Math.min(0.2, f.failures / 100) + (f.level >= 8 ? 0.05 : 0);
    return pick(Math.min(c, cap, 0.8), low.name);
  }

  return pick(0.2, 'weak_failure_signal');
}
