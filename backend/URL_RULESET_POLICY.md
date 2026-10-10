# 공학제 URL 규칙 변경 이력

현재 URL 규칙은 **1.3**이다. 아래 1.2 변경 이력과 비교 결과는 보존한다.
이번 공식 도메인·단축 URL 보완은 [URL 규칙 1.3](#url-규칙-13)에 기록한다.

## URL 규칙 1.2 (이전 변경)

`RULESET_VERSION`을 1.1에서 1.2로 올린다. 비교 기준은
`3d2bb415e670b04125db28212790daf5a581358f`의 운영 URL 규칙 1.1이며,
이 커밋을 연구 당시 평가 버전이라고 지칭하지 않는다. 연구 코드·데이터·기대값·
평판 스냅샷·결과는 변경하지 않고 이 규칙을 소급 적용하지 않는다.
포함 URL 연결 정책 2.0과 비URL 점수 규칙 2.0은 변경하지 않는다.

### 브랜드와 키워드

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

### 오프라인 비교와 민감도 한계

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

### 캐시와 실패

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

## URL 규칙 1.3

비교 기준은 `2509368d28508824301941f10743e6f29db80dda`의 URL 규칙 1.2다.
점수 규칙이 바뀌므로 `RULESET_VERSION`을 **1.2 → 1.3**으로 올린다.
이 기준 커밋을 연구 평가 버전으로 지칭하지 않으며 연구 코드·데이터·기대값·
평판 스냅샷·결과에는 소급 적용하지 않는다. 포함 URL 연결 정책 2.0,
비URL 점수 규칙 2.0, 30/70 판정, 100점 상한과 부모·포함 URL 최고 점수의
`max` 결합, 최대 3개 분석, 공유 시간 예산은 유지한다.

### 공식 근거와 적용 범위

아래는 사용자가 제공한 공식 자료와 설명을 기록한 것이다. 이번 작업에서는
링크에 접속하거나 PDF·도움말 원문을 열람하지 않았으며 독립적으로 검증하지 않았다.

- [카카오 공식 계열사 소개: Kakao ESG Report 2024](https://www.kakaocorp.com/media/esg-resource/pdf/Kakao_ESGReport2024_KR.pdf):
  카카오페이 주소를 `https://kakaopay.com`으로 안내한다는 제공 근거에 따라
  `kakaopay.com`을 카카오 브랜드의 공식 도메인 예외에 추가한다.
- [네이버 공식 도움말](https://help.naver.com/service/30041/contents/22827?lang=ko&osType=COMMONOS):
  `https://naver.me`를 단축 URL로 설명한다는 제공 근거에 따라 `naver.me`를
  네이버 브랜드 사칭 검사에서 제외하고 단축 URL 목록에도 추가한다.

브랜드 예외는 파싱한 hostname의 대소문자를 무시한 정확한 일치 또는
점으로 구분된 실제 하위 도메인에만 적용한다. `kakaopay.com.evil.invalid`,
`fakekakaopay.invalid`, `naver.me.evil.invalid`, `fakenaver.me`는 예외가 아니다.
경로·쿼리에 공식 주소가 있어도 호스트를 예외 처리하지 않는다.
예외는 브랜드 사칭 15점에만 적용하며 HTTP·userinfo·SQL/XSS·인코딩·포트·VT
등 다른 검사를 건너뛰거나 점수를 0으로 초기화하지 않는다.

`naver.me`와 점 경계의 하위 도메인에는 기존 단축 URL **20점**을 적용한다.
다른 단축 도메인과 가산 값은 변경하지 않는다. 기존 사유
‘단축 URL 서비스를 사용하고 있습니다.’는 그대로 유지하고, 단축 URL에는
‘단축 URL의 최종 목적지는 확인하지 않았습니다.’를 함께 안내한다.
리디렉션을 추적하거나 주소에 접속하지 않는다. 공식 단축 서비스라는 사실은
연결 대상의 안전성·소유권·HTTPS 지원을 확인했다는 뜻이 아니다.

### 오프라인 점수·사유 비교

VT 비활성, 캐시를 거치지 않는 실제 로컬 계산의 결과다. 사이트 접속·외부
평판 확인·최종 목적지 추적·VT 제출 결과가 아니다.

| 입력 | 1.2 점수·판정·사유 | 1.3 점수·판정·사유 |
| --- | --- | --- |
| `https://kakaopay.com` | 25 safe / 유명 서비스명을 포함하지만 공식 도메인으로 보기 어려운 주소입니다. | 10 safe / 로컬 URL 구조 규칙에서 추가 위험 신호가 발견되지 않았습니다. |
| `https://naver.me/AbCd1234` | 25 safe / 유명 서비스명을 포함하지만 공식 도메인으로 보기 어려운 주소입니다. | 30 warning / 단축 URL 서비스를 사용하고 있습니다. + 단축 URL의 최종 목적지는 확인하지 않았습니다. |

두 호스트 모두 `suspicious_brand_domain=false`이며 브랜드 사유가 제거된다.
`naver.me`는 `shortener=true`다. 30점 warning은 단축 구조의 불확실성을
반영하며 실제 피싱 탐지·안전성 확인을 의미하지 않는다. API `safe`의 앱
표시는 ‘낮은 위험’이고 안전성 보장이 아니다.

### 캐시·평판·이력과 검증

직접 URL과 포함 URL 모두 기존 버전 검증을 그대로 사용한다. 신선한 캐시라도
1.2 등 이전 버전이나 버전 누락이면 `ruleset_changed`로 1.3 로컬 점수를
재계산한다. 현재 1.3의 신선한 캐시는 재사용한다. 재계산 실패 시 이전 점수에
1.3 이름을 붙이지 않고 이전 캐시의 점수·버전을 보존한다. 직접 URL은 일반
503, 포함 URL은 부모·성공한 다른 링크를 유지하고 공개 실패 코드 및
`embedded_url_analysis_complete=false`를 제공한다.

이전 VT 위험 근거가 있으면 기존 정책대로 새 로컬 점수와 과거 VT 가산을
결합한다. 이번 조회 미완료·과거 정보 사용·과거 탐지 수를 구분하고 과거 조회
시각을 최신으로 갱신하지 않는다. VT 악성 3건의 과거 캐시가 있을 때
`kakaopay.com`은 로컬 25→10, 최종 95→80 danger이고 `naver.me`는
로컬 25→30, 최종 95→100 danger다. 로컬 위험 신호 부재 사유는 기존 보완처럼
로컬 규칙 범위로 한정하며 VT 위험·조회 실패·과거 정보 사용 근거를 보존한다.

점수·판정 변경은 기존 `ruleset_reclassified` 이력 저장 대상이다. 규칙만
바뀌고 점수·판정이 같으면 중복 생략을 유지한다. 최초 저장 실패 재시도와
저장 성공 뒤 캐시 완료 표시, 포함 URL의 부모 QR 이력 한 건 저장·상세 조회,
목록·통계 조회 정책은 바꾸지 않는다. 기존 이력의 일괄 수정이나 캐시 전체
삭제는 수행하지 않는다.

`test_analyze_qr.py`의 `OfficialBrandDomain13Tests`는 점수·사유·호스트 경계,
다른 위험 신호, 직접 URL·SMS·텍스트 API, 1.2/버전 누락 재계산·1.3 재사용·
실패·과거 VT 사용을 확인한다. 기존 VT 사유·캐시·시간 예산·이력 저장 및 조회
테스트도 유지한다. VT·DynamoDB는 mock/비활성화하고 외부 소켓 연결을 차단한다.
운영 Python 3.12 런타임·실제 AWS/VT 연동·제공 링크의 현행 내용은 미확인이다.
