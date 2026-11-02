# BYTE BACK 방어전 R5 7단계 자료실

이 저장소는 Supabase Auth 인증과 메모 CRUD를 Vercel 서버 함수 뒤에서 처리하고, 6단계 기기 등록 및 7단계 가상 위험 기반 접근 정책을 구현한 R5 프로젝트입니다. 브라우저 정적 파일에는 Supabase SDK와 공개 키가 없으며, 실제 학생 자료, 토큰, 비밀키를 코드나 브라우저 파일에 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고 저장소를 선택해 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 현재 단계 카드에 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/` 화면에서 Supabase 학습 계정으로 로그인할 수 있습니다. 브라우저는 `/api/auth/login`, `/api/auth/session`, `/api/auth/logout`을 호출하며, 서버가 Supabase Auth와 통신합니다. 액세스·갱신 토큰은 서버가 `HttpOnly`, `Secure`, `SameSite=Strict` 쿠키로 관리하고 응답 JSON에 반환하지 않습니다. 상태 변경 요청은 Origin 및 CSRF 검사를 거칩니다. 메모 자료는 `GET`·`POST /api/notes`와 `GET`·`PUT`·`DELETE /api/notes/{id}` 서버 함수만 사용합니다. 서버는 `src/verify-login.mjs`로 로그인 사용자를 확인하고, 목록·단건 조회·수정·삭제는 검증된 사용자의 메모에만 적용합니다. 메모 생성 시 소유자는 서버가 검증한 사용자 ID로 설정하며 요청 본문의 `owner_id`는 사용하지 않습니다. 기존 헤더 기반 인증 호환성도 유지합니다. `public/data.json`은 빌드에서 제거되며 더 이상 생성되지 않습니다.

단일 메모 API는 ID와 함께 `owner_id`를 데이터베이스 쿼리 조건으로 확인해 타인 메모와 존재하지 않는 메모에 동일하게 404를 반환합니다. 메모 API는 서버 전용 `SUPABASE_SECRET_KEY`를 사용하고, 이 키를 브라우저 파일이나 응답에 넣지 않습니다.

## 가상 메모 잔존 확인

다음 문장 네 개를 각각 정확한 문구로 검색하세요.

- `실습용 가상 과제 기록`
- `실습용 가상 포트폴리오 기록`
- `실습용 가상 리추얼 기록`
- `실습용 가상 행정 기록`

GitHub에서는 저장소의 **Code** 검색에서 기본 브랜치의 최신 파일을 대상으로 위 문장들을 하나씩 검색하세요. 현재 구성이라면 검색 결과는 이 확인 절차가 있는 README와 `supabase/migrations/`의 SQL에만 있어야 합니다. `data.json`은 빈 목록이고 `public/data.json`은 없어야 합니다.

Vercel에서는 **Deployments**에서 현재 Production 배포를 열고, 배포 주소의 `/`와 `/aleph.json` 등 정적 파일 내용에서 같은 문장을 검색하세요. 여기서는 문장이 나오지 않아야 하며 `/data.json`은 404여야 합니다. 기존 가상 메모 네 건과 B 계정 시험 메모 한 건은 Supabase 테이블에 보존되어 있습니다. 제작 1의 검증 결과 A 소유 메모 네 건, B 소유 메모 한 건입니다. 각 계정은 자기 메모만 조회할 수 있습니다. 로그인하지 않은 채 `/api/notes` 또는 `/api/notes/{id}`의 자료 요청을 보내면 JSON 인증 오류가 반환되어야 합니다.

## 5단계 검증 기록

Supabase에서 `public.learning_notes`에 대한 `PUBLIC`·`anon`·`authenticated` 직접 CRUD 권한을 회수하고 `service_role` CRUD 권한은 유지했습니다. 본인 소유 RLS 정책 네 개와 기존 A/B 계정 및 메모 다섯 건은 보존했습니다. 계정별 시험에서 A 메모 CRUD와 B 메모 조회가 정상 동작했고, 비로그인 서버 API는 HTTP 401, A/B 계정의 원본 Supabase REST API 직접 GET은 HTTP 403을 반환했습니다. 첫 화면 응답의 `X-Content-Type-Options: nosniff`도 실제 배포에서 확인했습니다. 이 결과는 배포 점검 기록이며, 로컬 테스트나 빌드만으로 대체할 수 없습니다.

인증 서버화에서는 브라우저 로그인·새로고침 후 세션 유지와 로그아웃, A 계정의 메모 추가·수정·삭제 및 B 계정의 기존 메모 조회를 Production에서 확인했습니다. 배포된 `/`와 `/app.js`에서 공개 키, Supabase SDK, JWT 패턴이 검출되지 않았습니다. `npm.cmd test`는 17개 테스트가 통과했고 `npm.cmd run build -- --local`도 성공했습니다. 이는 배포·계정 검증과 로컬 자동 테스트를 구분해 기록한 결과입니다.

이 절차는 GitHub 최신 파일과 현재 배포만 확인합니다. 옛 공개 커밋이나 이전 배포가 남아 있는 동안에는 과거 노출이 해소됐다고 쓰지 마세요. 과거 커밋과 이전 배포 주소도 별도로 확인하고, 남아 있다면 과거 노출은 계속된 것으로 취급해야 합니다.

## 6단계 · 등록 기기 기반 접근 정책

### 해결 과제

미등록 기기의 자료실 접근을 거부하는 정책을 구현했습니다.

### 구현 내용

- `src/decider.mjs`에 `device_registered` 규칙을 구현했습니다.
- 계약의 `deviceRegistered` 값이 정확히 `true`일 때만 `allow`를 반환합니다.
- `false` 또는 값이 누락된 경우 `deny`를 반환하고, 거부 사유는 `device_not_registered`입니다.
- 요청·응답 계약을 준수하며, `RULE_IDS`에는 구현한 `device_registered` 규칙을 등록합니다.

### 테스트 및 검증

- `npm.cmd run decider:test`: 가상 요청 2개 통과
- `deviceRegistered` 누락 입력: `deny` 확인
- `npm.cmd test`: 기존 17개 테스트 통과, 실패 0개

위 판정기 연습은 로컬 가상 요청 검증이며, 실제 운영 심판의 판정이나 실제 접속 통제를 증명하지 않습니다.

### 설계 근거

- Fail-Closed 원칙에 따라 등록 여부가 확인되지 않으면 거부합니다.
- 운영 엔진이 확인해 전달한 기기 등록 정보를 사용합니다.
- 클라이언트가 임의로 전달한 기기 상태를 신뢰하지 않습니다.

### 구현 범위와 한계

- 로컬 판정기 구현과 가상 요청 검증 범위입니다.
- 실제 mTLS 연결과 인증서 발급은 구현하지 않았습니다.
- 이 정책이 기존 Vercel 메모 API에 직접 연결된 것으로 간주하지 않습니다.
- 실제 심판 점수는 아직 확인하지 않았습니다.

### 재현 방법

Windows에서는 다음 명령으로 의존성을 설치하고 검증할 수 있습니다.

```shell
npm.cmd install
npm.cmd run decider:test
npm.cmd test
```

판정기 연습 결과에서 등록 기기의 정상 요청은 허용되고 미등록 기기의 가상 요청은 거부되는지 비교하세요.

### 포트폴리오 의미

- 정책 결정기(PDP) 구현
- 기기 기반 접근 제어
- 안전한 기본 거부 정책
- 자동화된 보안 검증

6단계 심판 결과는 사용자가 확인한 **100/100점**입니다. 이 점수는 이번 저장소 작업에서 독립적으로 재검증하지 않았습니다.

## 7단계 · 평소와 다른 접속은 다시 확인합니다

### 해결 과제와 구현

등록된 기기에서 발생한 가상 복합 이상 접속에 추가 확인을 요구하는 정책을 기존 판정기에 추가했습니다.

- `device_registered` 규칙을 유지해 `deviceRegistered === true`인 등록 기기는 기본적으로 허용하고, 미등록 또는 등록 여부가 없는 기기는 `device_not_registered` 사유로 거부합니다.
- `step_up_required` 규칙을 추가했습니다. 로컬 가상 사건 조건이 함께 맞고 유효한 재확인 정보가 없으면 `step_up`을 반환합니다.
- 등록 기기의 정상 가상 요청은 `allow`, 미등록 기기는 `deny`, 가상 복합 이상 요청은 `step_up`으로 판정합니다.
- 가상 복합 이상 요청에 계약상 범위의 `stepUp.verified`와 `stepUp.authAgeSeconds`가 있으면 가상 판정은 `allow`가 됩니다. 이는 실제 재로그인이나 세션 재검증을 뜻하지 않습니다.

### 입력 출처와 신뢰 경계

판정기는 `docs/DECIDER_REQUEST.md`에 정의된 `deviceRegistered`, `signals`, `recentEvents`, `stepUp`만 사용합니다. 엔진이 전달하는 입력을 검사하며, 계약에 없는 클라이언트 필드를 추가하거나 읽지 않습니다.

- `signals.source: "judge_fixture"`는 로컬 가상 사건 분류에만 사용하며 실제 위치 증거로 취급하지 않습니다.
- `source: "none"` 및 `region`·`network`의 `unknown`은 위치·네트워크가 확인되지 않은 상태이며 정상 접속의 증거로 사용하지 않습니다. 그 밖에 확인되지 않은 출처도 신뢰 가능한 위치 증거로 승격하지 않습니다.
- 위험 검사는 기존 입력 구조 검사 결과를 사용합니다. 잘못되었거나 누락된 신호·사건은 정상값으로 보정하지 않으며 위험 근거로 사용하지 않습니다. 다만 잘못된 입력을 차단할 공식 이유 코드와 처리 규칙은 확인되지 않았습니다.
- 로컬 복합 위험 조건은 `judge_fixture`, `network: "unusual"`, `hour: 3`, 그리고 `risk_signal` 사건의 `count: 20`, `ageSeconds: 60`이 모두 맞는 경우입니다. 지역 값 하나만으로 `step_up`을 요구하지 않습니다.

이 고정값은 기존 가상 fixture를 재현하기 위한 사례일 뿐, 운영에서 검증된 위험 임계값이나 범용 위험 점수가 아닙니다.

### 테스트 및 검증 기록

다음은 이번 단계에서 실제 실행한 로컬 확인이며, 운영 연결이나 심판 판정이 아닙니다.

- `npm.cmd run fixture:7`: 정상 사건 `allow`, 복합 이상 사건 `step_up`
- `npm.cmd run decider:test`: 등록 기기 허용, 미등록 기기 거부, 복합 이상 `step_up`, 재확인 정보가 있는 가상 요청 허용 등 4개 사례 통과
- `npm.cmd test`: 기존 17개 테스트 통과, 실패 0개
- `node --check src/decider.mjs`: 통과
- 추가 가상 경계 사례 13개: 미등록·누락 기기, 지역 단독, `source: "none"` 및 미확인 출처, 잘못되거나 누락된 위험 입력, 재확인 상태 등을 확인
- `npm.cmd run decider`: `package.json`에 해당 스크립트가 없어 실행 실패. 등록된 판정기 연습 명령은 `npm.cmd run decider:test`입니다.

### 구현 범위와 한계

- 판정기와 fixture는 로컬 가상 요청을 다루며 실제 Vercel 메모 API와 연결되지 않습니다.
- 실제 재로그인, 동일 사용자·세션의 재인증 시각 검증, `step_up` 이전 메모 접근 차단은 구현되지 않았습니다.
- `step_up.verified`와 `authAgeSeconds`를 검사하는 로직은 가상 요청 입력 검사이며, 재로그인 완료 증명이 아닙니다.
- 운영 `allowedReasonCodes` 등록부에서 `approved`, `device_not_registered`, `step_up_required`가 허용되는지는 확인되지 않았습니다.
- 7단계 최종 심판 결과는 아직 확인되지 않았습니다. 로컬 통과 결과로 심판 점수를 추정하지 않습니다.

### 포트폴리오 의미

- 정책 결정기(PDP)에서 기기 등록 정책과 위험 기반 추가 확인 분기를 함께 설계하는 역량
- 입력 계약 검증, 출처별 신뢰 경계, fail-closed 기기 거부를 고려하는 보안 설계 역량
- 가상 fixture와 회귀 테스트로 정책 동작을 검증하고 운영 미연동·미확인 계약을 명확히 문서화하는 AI Agent 개발 역량

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`과 `api/`의 서버 함수를 배포합니다. `npm run build`는 1단계 이후 설정에서도 동작하며, Vercel이 제공하는 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증해 `public/aleph.json`을 계속 생성합니다. 검증 정보가 없으면 빌드가 실패하므로 빈 주소를 내보내지 않습니다. `aleph.json`만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다.

Vercel 프로젝트의 **Settings → Environment Variables**에 `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`를 설정하세요. 실제 값을 저장소, 브라우저 코드, API 응답, 로그에 기록하지 마세요. 두 Supabase 키는 서버 함수에서만 사용하며, `SUPABASE_SECRET_KEY`는 메모 데이터베이스 요청에만 사용합니다.

테스트는 `npm.cmd test`로 실행하고, 로컬 정적 빌드는 `npm.cmd run build -- --local`로 확인합니다. 로컬 빌드는 `/aleph.json`을 만들지 않으며, Vercel 서버 함수 실행이나 배포를 증명하지 않습니다. `npm.cmd run bundle`의 비로그인 `/api/notes` 요청은 학생의 자기 점검이며 심판 판정이 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
