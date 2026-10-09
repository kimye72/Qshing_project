# 공학제 URL 규칙 1.2

`RULESET_VERSION`을 1.1에서 1.2로 올린다. 비교 기준은
`3d2bb415e670b04125db28212790daf5a581358f`의 운영 URL 규칙 1.1이며,
이 커밋을 연구 당시 평가 버전이라고 지칭하지 않는다. 연구 코드·데이터·기대값·
평판 스냅샷·결과는 변경하지 않고 이 규칙을 소급 적용하지 않는다.
포함 URL 연결 정책 2.0과 비URL 점수 규칙 2.0은 변경하지 않는다.

## 브랜드와 키워드

- 브랜드 가산은 URL을 파싱한 호스트에 구체적인 식별자
  `naver`, `kakao`, `google`, `apple`, `paypal`이 포함되어 있고,
  해당 브랜드의 공식 도메인이 아닌 경우에만 기존대로 15점이다.
  일반 단어 `pay`, `bank`는 특정 브랜드 식별에서 제외한다.
  경로·쿼리·프래그먼트·사용자 정보의 브랜드 이름은 호스트 사칭 근거가 아니다.
- 공식 도메인 예외는 대소문자를 무시한 정확한 호스트 또는
  `.`으로 구분된 하위 도메인에만 적용한다. `fakepaypal.com`이나
  `paypal.com.evil.invalid`에는 예외를 적용하지 않는다.
  Google 공식 예외에 `google.co.kr`을 추가한다.
  [Google 공식 안내](https://support.google.com/youtube/answer/4358949?hl=ko)는
  Google.co.kr을 Google 검색 웹사이트로 안내한다.
- 공식 호스트도 기본 점수와 HTTP·userinfo·인코딩·SQL/XSS·포트·평판 등의
  다른 검사를 모두 수행한다. 공식 도메인에 대한 전체 점수 초기화는 없다.
- `gift`, `free`, `event`, `coupon`은 정상 행사 페이지에도 쓰이는 약한 신호다.
  각 단어를 기존 부분 문자열 10점에서 토큰당 5점으로 변경한다.
  파싱한 호스트 및 개별 디코딩한 경로·쿼리·프래그먼트에서 검사하고
  스킴·userinfo는 제외한다. ASCII 영숫자에 붙어 있는 부분 문자열은
  매칭하지 않는다. 같은 단어는 여러 위치에 있어도 한 번만 가산한다.
  필드 경계를 디코딩된 구분자로 다시 해석하지 않는다.
- `login`, `verify`, `update`, `secure`, `account`, `bank`, `password`,
  `wallet`은 기존 원문·디코딩 URL의 부분 문자열 검사와 단어당 10점을 유지한다.
  `bank` 일반 키워드와 특정 브랜드 사칭은 구분한다.

URL 기본 10점, 나머지 위험 신호·VT 가산·100점 상한, warning 30점 / danger
70점 기준은 유지한다. QR 부모와 성공한 포함 URL의 최고 점수는 기존대로
`max(parent_score, embedded_url_max_score)`로 결합한다.

## 오프라인 비교와 민감도 한계

아래는 VT 비활성, 캐시를 거치지 않는 로컬 계산의 1.1 / 1.2 비교다.
실제 사이트 방문·평판 확인·VirusTotal 제출 결과가 아니다.

| 입력 | 1.1 | 1.2 |
| --- | --- | --- |
| `https://paypal.com` | 25 safe | 10 safe |
| `https://google.co.kr` | 25 safe | 10 safe |
| `https://wooribank.com` | 35 warning | 20 safe |
| `https://daegu.ac.kr/event/free` | 30 warning | 20 safe |
| `https://fakepaypal.invalid/login` | 35 warning | 35 warning |
| `https://paypal.com.evil.invalid/login` | 35 warning | 35 warning |
| `https://fakepaypal.invalid/event/free` | 45 warning | 35 warning |
| `http://paypal.com` | 45 warning | 30 warning |
| `https://user@paypal.com` | 50 warning | 35 warning |
| `https://paypal.com/?q=%3Cscript%3E` | 40 warning | 25 safe |
| `https://freegift.invalid` | 30 warning | 10 safe |

PayPal script 입력은 잘못된 브랜드 15점만 제거한다. 인코딩 5점과 script
패턴 10점, 판단 사유와 `sql_xss_pattern_count=1`은 유지된다. safe로 내려가는
것을 피하기 위한 임의 점수 가산은 하지 않는다. 이 휴리스틱의 safe는 실제
안전성 보증이 아니다. 단독 script 신호나 결합된 약한 유인 단어만 있는
주소의 탐지 민감도가 낮아질 수 있다. 브랜드 신호 하나만 있는
`fakepaypal.com`은 기존처럼 25점 safe다. 브랜드 목록·공식 도메인 목록은
제한적이며, 콘텐츠·리디렉션·실제 소유권·TLS 지원은 확인하지 않는다.
강한 키워드 부분 문자열 검사로 인한 다른 오탐 가능성도 남아 있다.

## 캐시와 실패

- 직접 URL과 QR 본문 URL은 같은 버전 검증 경로를 사용한다.
  신선한 캐시라도 `ruleset_version`이 현재 문자열 `1.2`와 다르거나
  누락되면 `ruleset_changed`로 재계산한다. 오래된 버전의 점수를
  현재 버전으로 이름만 바꿔 반환하지 않는다.
- 계산 결과의 버전이 없거나 현재 버전과 다르면 분석 실패로 처리한다.
  캐시 저장·복원도 현재 버전을 확인하며 누락 버전에 기본값을 붙이지 않는다.
  점수·판정·규칙 버전은 동일한 DynamoDB update로 저장한다.
  현재 버전의 신선한 캐시는 기존대로 재사용한다.
- 재계산 실패 시 이전 분석 점수·버전은 덮어쓰지 않는다. 직접 URL API는
  내부 오류를 제외한 일반 503 응답을 반환하고 점수·버전을 제공하지 않는다.
  QR 본문에서는 부모와 성공한 다른 URL 결과를 보존하며 고정 실패 코드와
  `embedded_url_analysis_complete=false`를 반환한다. 실패한 URL에
  현재 버전의 분석 결과가 있는 것처럼 표시하지 않는다.
  직접 스캔 횟수 같은 기존 요청 메타데이터 갱신은 유지한다.
- 재계산 성공 후 캐시 쓰기만 실패하면 계산한 현재 버전 결과를 반환한다.
  저장소에 남은 이전 버전은 다음 요청에서도 재계산 대상이다.
- VT 비활성/불가 상태에서 이전 캐시에 평판 통계가 있으면 기존 정책대로
  새 규칙의 로컬 점수와 과거 VT 통계를 다시 결합한다. 과거 로컬 점수를
  재사용하지 않으며 VT 조회 시각을 최신으로 바꾸지 않는다.
  이 경우 `cache_revalidated=false`로 평판 재검증이 완료됐다고 표시하지 않는다.
  같은 규칙의 오래된 캐시에서 VT를 사용할 수 없을 때 재검증을 유예하는
  기존 정책도 유지하므로, 현재 버전이라고 항상 최신 평판인 것은 아니다.
- 원본 후보·`assumed_https` 및 HTTPS 가정 사유는 요청별 응답에서만
  붙인다. 같은 주소의 명시적 HTTPS 요청과 HTTPS 가정 요청 사이에
  캐시를 통해 이 정보가 섞이지 않는다.

검증은 `backend/test_analyze_qr.py`의 브랜드·키워드·캐시 및 API 회귀
테스트로 수행한다. 외부 연동은 mock/비활성화하고 소켓 연결도 차단한다.
운영 Python 3.12 실행과 실제 DynamoDB/Lambda 연동은 별도 확인 항목이다.
