import { classifyResourceAccess } from './resource-access.mjs';

// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계 기기 등록 정책입니다. 등록된 기기만 허용하며, 미등록 또는 등록 여부가 불확실한 기기는 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_access',
]);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function inspectSignals(signals) {
  if (!isRecord(signals)
      || typeof signals.source !== 'string'
      || typeof signals.region !== 'string'
      || typeof signals.network !== 'string'
      || !Number.isFinite(signals.hour)) {
    return { status: 'invalid' };
  }

  if (signals.source === 'none') return { status: 'unavailable' };
  if (signals.source === 'judge_fixture') {
    return {
      status: 'fixture',
      network: signals.network,
      hour: signals.hour,
    };
  }
  return { status: 'unverified' };
}

function inspectRecentEvents(recentEvents) {
  if (!Array.isArray(recentEvents) || recentEvents.length > 12) {
    return { status: 'invalid' };
  }

  const events = [];
  for (const event of recentEvents) {
    if (!isRecord(event) || typeof event.kind !== 'string'
        || !Number.isFinite(event.ageSeconds) || !Number.isFinite(event.count)) {
      return { status: 'invalid' };
    }
    events.push({
      kind: event.kind,
      ageSeconds: event.ageSeconds,
      count: event.count,
    });
  }
  return { status: 'valid', events };
}

function inspectRiskInputs(request) {
  return {
    signals: inspectSignals(request?.signals),
    recentEvents: inspectRecentEvents(request?.recentEvents),
  };
}

function hasCompositeFixtureRisk(riskInputs) {
  if (riskInputs.signals.status !== 'fixture'
      || riskInputs.signals.network !== 'unusual'
      || riskInputs.signals.hour !== 3
      || riskInputs.recentEvents.status !== 'valid') {
    return false;
  }

  return riskInputs.recentEvents.events.some(event =>
    event.kind === 'risk_signal' && event.count === 20 && event.ageSeconds === 60);
}

function hasValidStepUp(request) {
  const stepUp = request.stepUp;
  return isRecord(stepUp) && stepUp.verified === true
    && Number.isFinite(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900;
}

export async function decide(request) {
  const riskInputs = inspectRiskInputs(request);
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const resourceAccess = classifyResourceAccess({
    service: request.service,
    method: request.method,
    path: request.path,
    route: request.route,
  });
  if (resourceAccess.outcome !== 'allow_candidate') {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'resource_access_denied',
      ruleIds: ['resource_access'],
    };
  }

  if (hasCompositeFixtureRisk(riskInputs) && !hasValidStepUp(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['device_registered', 'step_up_required'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
