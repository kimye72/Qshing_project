# 포함 URL 분석 연결 정책 2.1

## 2.1: 한글 URL 값과 포트 보존

2026-10-11, 비교 기준 `ce941916def7542d98021740df808f018835c66d`에서
한글 경로·쿼리가 잘리거나 포트 주소가 누락되는 결함을 보완했다. 연구 자료와
과거 저장 이력은 수정하지 않는다. 아래 2.0 도입 및 이력 계약의 변경 이력도
유지한다. 현재 URL 점수 규칙은 **1.5**이며, 30/70 기준·`max` 결합·최대 3개
분석·시간 예산·캐시 버전 및 이력 정책은 바꾸지 않는다.

- ASCII 도메인 검증은 유지하고 `domain[:port][/path][?query][#fragment]`를
  구분한다. 경로·쿼리·fragment에는 한글도 허용하며 공백·따옴표 등 토큰 경계까지
  보존한다. 대소문자, `&`, `=`, `+`, 기존 퍼센트 인코딩을 재작성하지 않는다.
- 포트는 ASCII 숫자와 값 1–65535를 검증한다. 잘못된 포트가 붙으면 전체 후보를
  제외하며 도메인만 잘라 분석하지 않는다. URI 제외의 예외는 검증된
  `domain:port` 형태에만 적용한다. 다른 URI·이메일·파일명 제외는 유지한다.
- 일반 텍스트의 이미 드러난 URL 값은 디코딩하지 않는다. 구조형 QR은 원시
  필드 경계를 먼저 분리하고 query `body`의 바깥 인코딩을 한 번 해제한다.
  이후 기존 최대 3회 디코딩 범위 안에서 아직 인코딩된 본문/URL 구조를 드러내되,
  이미 URL 구조가 드러난 토큰의 `%26`, `%3F`, `%2F` 등은 보존한다. SMS colon-message와
  SMSTO에서도 이미 보이는 URL 값은 그대로 둔다. 본문을 바깥 수신자·제목 필드로
  다시 나누지 않는다. 기존 구조형 미리보기용 디코딩은 유지하고 분석 주소는
  보존형 본문 추출을 사용한다.
- 본문의 URL 구조를 인코딩하려면 구조 구분자(`/`, `?` 등)도 함께 인코딩한다.
  이미 보이는 URL의 `%xx`는 URL 값으로 취급하므로 그 값을 다시 디코딩해
  의도한 주소를 추측하지 않는다. 공백 없이 경로 뒤에 붙은 `에서` 같은 조사도
  한글 경로와 구분할 수 없어 경로에 포함한다. 링크와 설명은 공백으로 분리한다.
- `original_url`/`original_candidates`에는 HTTPS를 붙이지 않는다.
  `analysis_url`과 `assumed_https`로 분석 주소를 구분하며 실제 HTTPS 지원은
  확인하지 않는다. 앱 링크 열기는 해당 결과의 전체 `analysis_url`을 사용한다.

| 입력 후보 | 2.0 추출 | 2.1 분석 주소 |
| --- | --- | --- |
| `example.com/배송조회?token=AbC` | `example.com/` | `https://example.com/배송조회?token=AbC` |
| `example.com/track?next=배송조회` | `example.com/track?next=` | `https://example.com/track?next=배송조회` |
| `example.com:8443/login` | 후보 없음 | `https://example.com:8443/login` |

연결 정책 버전은 2.1로 반환/저장하며 기존 2.0 기록은 유지한다. 점수 캐시는
전체 보존 주소를 키로 사용한다. 과거 잘린 주소의 캐시를 새 전체 주소로
재해석하거나 옛 이력의 원본을 복원하지 않는다. SDK·브라우저의 실제 URI 처리와
연결 대상은 오프라인 테스트로 확인하지 않는다.

## 2.0 도입 이력

이 문서는 공학제 시연용 분석 경로의 변경을 기록한다. 연구 당시 버전의
코드·데이터·기대값·평판 스냅샷·결과에 소급 적용하지 않는다.
이번 변경의 비교 기준 커밋은 `70e2a24000cae4efabb9426f2e3ff77a6c4fba76`이다.
이 커밋을 연구 당시 평가 버전의 식별자로 지칭하지 않는다.

기존 경로에서는 스킴 없는 후보가 `extracted_url_candidates`에 표시되지만
URL 분석과 캐시에 전달되지 않았다. 정책 2.0에서는 기존 후보 검증을 통과한
문자열에 `https://`를 가정하여 기존 URL 분석·캐시 경로로 전달한다.
HTTPS 지원 여부, 도착지 또는 실제 안전성을 확인했다는 의미가 아니다.

- 일반 텍스트의 명시적 HTTP/HTTPS 링크와 검증된 후보를 분석한다.
- SMS, SMS colon-message, SMSTO, mailto는 필드 경계를 먼저 나눈 뒤 디코딩한
  본문에서만 분석 대상을 추출한다. 수신자·이메일 제목·Wi-Fi SSID는 분석
  대상이 아니다. 공개 추출 필드는 기존처럼 콘텐츠 전체의 추출 정보를
  나타내므로 본문 분석 개수와 다를 수 있다.
  SMS 쿼리의 `body` 값(빈 값 포함)이 우선하며, colon-message 대체 파싱의
  구분자는 원시 수신자 구간에서만 찾는다. 쿼리의 제목·기타 필드 값 안에
  있는 콜론이나 URL은 본문 시작으로 재해석하지 않는다.
- 다른 URI 스킴, 이메일 주소, 기존 검증에서 제외하는 파일명·문자열을
  HTTPS 후보로 변환하지 않는다.
- 명시적 링크를 먼저 선택하고 후보를 추가한다. 스킴·호스트만 소문자화한
  분석 주소로 중복 제거한다. 경로·쿼리·프래그먼트·사용자 정보의 대소문자와
  URL 구분자는 보존한다. HTTP와 HTTPS는 서로 다른 주소다.
- 공개 후보 목록은 기존처럼 최대 10개이고, 후보 수는 전체 검증된 후보 수다.
  본문 분석은 공개 목록의 제한 이전 후보를 사용한다. 명시적 링크와 후보를
  합쳐 최대 3개 주소만 호출하며 실패한 호출도 이 제한에 포함된다.
- 부모 점수와 포함 URL 최고 점수의 `max`를 적용한다. 연결 정책 2.0 도입
  당시에는 `RULESET_VERSION=1.1`, `NON_URL_SCORING_VERSION=2.0`을 유지했다.
  이후 URL 규칙 1.2의 브랜드·키워드 및 캐시 변경은
  [URL_RULESET_POLICY.md](URL_RULESET_POLICY.md)에 별도로 기록한다.
  30/70 판정 기준과 `max` 결합, 비URL 점수 규칙 2.0은 계속 유지한다.
  스킴 생략 자체의 점수 가산은 없다. 예를 들어 `bit.ly/3abcde`는 VT 비활성
  조건에서 URL 기본 점수 10과 기존 단축 URL 점수 20을 적용받는다.

`/analyze-qr` 응답의 `embedded_url_policy_version`은 연결 정책 버전이다.
`contains_url`과 `extracted_urls`는 명시적 링크 추출 의미를 유지하며, 가정한
HTTPS 주소를 이 필드에 추가하지 않는다. `extracted_url_candidates`는 원본
후보의 호스트·경로·쿼리 대소문자를 보존한다. 후보 중복 제거는 호스트에만
대소문자 무시를 적용한다.

포함 URL별 결과에는 `original_url`, `original_candidates`, `analysis_url`,
`assumed_https`를 제공한다. 명시적 링크와 후보가 같은 분석 주소이면 한 번만
호출하고 해당 후보는 `original_candidates`에 남긴다. `assumed_https`는 이
주소로 합쳐진 후보에 HTTPS 가정을 적용했다는 뜻이다. 가정 사유는 응답을
구성할 때 추가하므로 URL 캐시의 판단 사유를 수정하지 않는다.

분석 실패 시 부모 점수와 기존 본문 결과를 보존하고, 성공한 다른 URL의
점수는 결합한다. `embedded_url_failures`에는 대상 메타데이터와 고정 오류
코드 `EMBEDDED_URL_ANALYSIS_FAILED`만 반환한다. 내부 예외 내용은 반환하지
않는다. 실패 또는 3개 제한에 따른 제외가 있으면
`embedded_url_analysis_complete=false`이며 판단 사유에 미완료를 표시한다.
`analysis_flags`의 실패·제외 개수와 정책 버전은 기존 이력 저장 경로에도
전달된다. 연결 정책 2.0 도입 시에는 개수·최고 점수만 이력에 저장했으며
원본 후보·본문·URL 목록을 새 DB 필드로 저장하지 않았다. 이후 링크별
이력 저장 보완은 아래 계약을 따른다. 분석 연결 정책 버전 자체는 바뀌지 않는다.

## 포함 URL 이력 상세 저장·조회 계약

비교 기준은 `c94a363e6a1c2282b460ad26f0ca3e98f2795a33`이다. 이 보완은
연구 당시 평가에 소급 적용하지 않으며 분석 점수·URL 규칙 1.2·30/70 기준,
`max` 결합·최대 3개 분석·공유 시간 예산을 변경하지 않는다.

`save_scan_result`는 부모 QR 한 건에 아래 필드를 보존하고 `GET /scans`의
`items`에서도 같은 필드로 반환한다. 자식 이력을 따로 만들거나 조회 시
URL 분석·VT 조회를 다시 수행하지 않는다. 정렬·페이지·통계 집계 방식과
직접 URL 이력의 저장 실패 재시도·중복 생략 정책은 유지한다.

- `embedded_url_results`, `embedded_url_failures`
- `embedded_url_analysis_complete`, `embedded_url_policy_version`
- `embedded_url_count`, `analyzed_embedded_url_count`, `embedded_url_max_score`
- 기존 `analysis_flags.embedded_url_failed_count`,
  `analysis_flags.embedded_url_skipped_count` 등 분석 플래그. 제한 제외는
  분석 실패와 구분하며 제외된 주소 목록을 새로 만들어 저장하지 않는다.

성공 항목은 기존 `EmbeddedUrlResult` 모델의 공개 필드를 명시적으로
선별한다. `original_url`, `original_candidates`, `analysis_url`,
`assumed_https`, `url`, `domain`과 로컬·VT 가산·최종·호환 점수, 판정·사유,
규칙 버전, VT 가용 여부·조회 상태·출처·4종 탐지 수, 캐시 적중·경과 시간·
재검증·사유를 보존한다. `analysis_flags`는 현행 URL 규칙 플래그,
`historical_reputation_used`, `analysis_budget_exhausted`의 숫자·불리언·null
값만 선택한다. 향후 새 플래그는 저장 허용 목록을 검토해 추가해야 한다.
자식의 내부 제어 필드, 예외 원문, 자격증명 필드, `raw_result`나 전체 외부
응답은 저장·조회하지 않는다. 기존 부모 요약·원본 결과 저장 정책은 유지한다.

실패 항목은 `EmbeddedUrlFailure` 모델의 원본 링크·후보, 분석 주소,
HTTPS 가정 여부와 공개 코드 `EMBEDDED_URL_ANALYSIS_FAILED`만 보존한다.
점수나 VT 성공 정보를 추가하지 않는다. 부모와 각 자식의 점수·평판은
각각 저장하며 서로 복사하거나 덮어쓰지 않는다. `vt_available=false`일 때
0인 탐지 수는 조회 성공이나 확인된 악성 탐지 0건을 뜻하지 않는다.

조회 응답의 `embedded_url_details_available`은 결과·실패 목록이 모두
저장된 목록인지 나타내는 파생 값이다. 과거 기록과 새 무링크 기록을 구분한다.

| 기록 | details_available | results / failures | analysis_complete | policy_version |
| --- | --- | --- | --- | --- |
| 상세 필드 없는 과거 기록 | false | null / null | null | null |
| 새 API로 저장한 포함 URL 없는 QR·직접 URL | true | [] / [] | true | 2.1 |
| 일부 실패·제한 제외가 있는 새 기록 | true | 성공·실패 목록 | false | 2.1 |

일부 필드만 있는 기록은 저장된 필드만 반환한다. 누락된 목록은 빈 목록으로,
누락된 완료 여부는 true로 보완하지 않는다. 상세 목록이 있어도 완료 여부가
없으면 null이다. 완료 여부를 과거 `analysis_flags`나 개수에서 추론하지 않는다.
과거 정책 버전과 요약 개수·최고 점수는 그대로 유지한다. 필드를 제공하지
않는 직접 저장 호출도 미확인 정보를 생성하지 않는다. 기존 기록의 상세는
복원하거나 재계산하지 않는다.

중첩 목록·객체는 기존 재귀 변환과 DynamoDB 타입으로 저장하고, 조회 시
Decimal을 JSON 숫자로 변환한다. false·0·빈 목록·빈 플래그 객체는 보존한다.
부모 저장에 추가 DB 호출을 넣지 않는다. 저장 실패는 기존 DATABASE_ERROR
응답을 유지하며 직접 URL 완료 표시도 실제 저장 성공 뒤에만 수행한다.

검증은 `backend/test_analyze_qr.py`의 회귀 테스트를 사용한다. VT, DynamoDB와
실제 URL 접속을 차단하거나 mock한 조건에서 실행한다. 외부 평판이나 운영
배포 여부를 이 테스트의 결과로 주장하지 않는다.
이력 상세는 `test_embedded_url_history.py`에서 실제 저장·조회 함수와 DynamoDB
타입 직렬화·역직렬화기를 사용해 검증하며 SDK 테이블·VT는 mock한다.
`test_direct_url_history.py`의 연속 요청 저장 실패 복구 테스트도 함께 유지한다.
