# 저장 이력 목록·통계 조회 정책

비교 기준은 `d800e93650b1903facda9b19f0ad4ef1383c6b62`이다. 기존 코드는
Scan 한 페이지에 `Limit=N`을 지정하고 그 페이지만 시간순으로 정렬했다.
Scan 순서는 생성 시각 순서가 아니며 Limit은 필터 전 평가 항목 수다.
예를 들어 첫 페이지에 10월 1일 기록, 다음 페이지에 10월 10일 기록이 있으면
기존 `limit=1`은 10월 1일을 최신으로 반환했다. 필터 후 빈 페이지에 다음
키가 있어도 조회를 끝냈다. 통계도 같은 일부 기록만 집계했다.

## 확인한 구조와 조회 상한

저장소의 공개 코드·설정·문서에는 테이블 생성 정의, 시간순 Query에 적합한
GSI/LSI 또는 IndexName 설정이 없다. 저장 코드는 UUID `scan_id`와 UTC ISO
`created_at`을 기록하지만 실제 운영 테이블의 키·인덱스 정의를 확인한 것은
아니다. 운영 DescribeTable·인덱스 생성·테이블 변경·데이터 일괄 수정은 하지
않는다. 확인된 시간순 인덱스가 없으므로 제한된 전체 Scan을 사용한다.

| 제한 | 값 |
| --- | --- |
| 조회 전체의 monotonic 시간 예산 | 8초 |
| 응답 준비·직렬화용 여유 | 마지막 1초 |
| 최대 페이지 수 | 20 |
| 최대 평가 항목 수 | 4,000 |
| 한 페이지의 평가 Limit | 최대 200, 남은 평가 상한에 맞춰 감소 |
| SDK 연결+읽기 배분 | 최대 0.75초, 남은 예산에 맞춰 감소 |
| SDK 총 시도 | 1회 |

페이지·필터·통계마다 예산을 새로 시작하지 않는다. SDK resource 생성 전,
Scan 시작 전·반환 후, 변환·정렬·집계 후에 같은 마감 시각을 검사한다.
각 페이지는 남은 예산으로 SDK Config를 다시 만들며 저장 경로의 Config나
분석 요청의 12초 예산·점수·캐시·이력 저장 정책은 바꾸지 않는다.
바깥 요청 예산이 이미 있다면 그 시계와 더 이른 마감도 따른다.

SDK socket timeout은 전체 실행을 강제 취소하지 않는다. DNS·자격증명
조회·resource 생성·느린 연속 수신·SDK 내부 처리·스케줄링이 배분을 넘길 수
있다. Config 배분은 resource 생성 전에 정해지므로 생성 지연 후 남은
시간보다 클 수도 있다. 반환 후 초과를 감지하면 추가 호출과 결과 반환을
중단한다. 8초는 협력적 조회 예산이며 HTTP 수신·스레드 대기·cold start·
응답 전달까지의 절대 상한을 보장하지 않는다.

## 목록 계약

`GET /scans?limit=20&status=danger`는 관리자 `X-Admin-Key` 인증을 유지한다.
limit은 반환할 최신 저장 이력의 최대 개수다. 목록 API 범위는 1~100이고
기본값은 20이다. status는 safe/warning/danger이며 없으면 전체 상태다.

LastEvaluatedKey가 끝날 때까지 조회한다. 빈 필터 페이지도 이어서 조회하며,
이미 N개를 찾았어도 뒤쪽 페이지의 더 최신 기록을 확인한다. ScannedCount는
필터에서 제외된 항목도 비용 상한에 포함한다. 평가 개수를 확인할 수 없는
잘못된 응답도 정상 완료로 취급하지 않는다.

동일 scan_id의 같은 항목은 중복 제거하고 다른 내용이면 미완료로 처리한다.
다음 키 반복·순환은 중단한다. ID 없는 과거 항목은 전체 저장 내용의 정규화된
표현으로 동일 복사본만 제거한다. 전체 확인 후 created_at 내림차순, 동일
시각이면 scan_id 내림차순으로 정렬해 N개를 선택한다. ISO 시간대는 UTC로
비교하며 timezone 없는 과거 ISO 시각은 UTC로 해석한다. 필터 일치 기록에
누락·해석 불가 시각이 있으면 최신 N건을 보장할 수 없으므로 미완료 503으로
처리한다. 기록 시각을 생성하거나 끝으로 밀어 순위를 추정하지 않는다.
과거 기록의 점수·평판·포함 URL 상세 누락은 기존 조회 호환성을 유지한다.

성공 응답은 기존 `items`에 `metadata`를 추가한다. 포함 URL 상세·실패 목록·
HTTPS 가정 정보와 과거 기록의 null 호환 계약은 유지한다.

```json
{
  "items": [],
  "metadata": {
    "scope": "latest_saved_history",
    "count_unit": "stored_history_records",
    "requested_limit": 20,
    "returned_count": 0,
    "status_filter": null,
    "query_complete": true,
    "pages_read": 1,
    "evaluated_items": 0,
    "matching_records_count": 0,
    "ordering": "created_at_desc_scan_id_desc",
    "read_consistency": "strong_per_item_not_snapshot",
    "bounds": {
      "time_budget_seconds": 8.0,
      "max_pages": 20,
      "max_evaluated_items": 4000,
      "page_evaluation_limit": 200
    }
  }
}
```

필터 사용 시 scope는 `latest_saved_history_for_status`, status_filter는 해당
상태다. matching_records_count는 이번 전체 순회에서 확인한 중복 제거 후
필터 일치 기록 수, returned_count는 그중 선택한 최대 N개다. 일부 필드 없는
과거 항목을 최신 시각으로 보완하지 않는다.

ConsistentRead=true는 개별 읽기의 강한 일관성이다. 설치된 botocore의 Scan
서비스 명세도 snapshot isolation을 보장하지 않는다고 명시한다. 따라서
query_complete=true는 페이지 순회가 끝났다는 뜻이며 특정 시점의 원자적
스냅샷은 아니다. 조회 중 추가·수정·삭제가 있으면 요청 간 결과가 달라지거나
그 변경을 모두 반영하지 못할 수 있다. 같은 ID의 충돌은 감지하지만 모든
동시 변경을 감지할 수는 없다.

## 통계 계약

`GET /scans/summary?limit=200`의 limit은 최근 N개 저장 이력의 집계 범위다.
기본 200, 허용 1~500이다. 같은 조회 경로에서 최신 집합을 한 번 선택해
total·safe·warning·danger·unknown·부모 VT 합계를 계산한다. recent_items는
그 집계 집합에서 최신 최대 10개 미리보기이며 별도로 조회하지 않는다.

total은 실제 집계한 저장 이력 수이며 테이블 전체 건수·전체 요청 횟수가
아니다. 직접 URL의 동일 결과 요청은 저장을 생략할 수 있다. URL 캐시의
scan_count는 직접 요청 횟수이고 이 통계와 별개다. 포함 URL은 부모 QR 한
건으로 저장된다. vt_malicious_total·vt_suspicious_total은 부모 이력 필드의
합계이며 자식 탐지 수를 더하거나 자식 통계를 부모에게 복사하지 않는다.
평판 미확인 기록의 0은 악성 탐지 0건을 확인했다는 의미가 아니다.

기존 summary 필드에 목록과 같은 metadata를 추가한다. requested_limit과
returned_count 외에 aggregated_count(=total), vt_totals_scope=
`parent_history_records`, recent_items_limit=10을 제공한다. scope는
`latest_saved_history`, count_unit은 `stored_history_records`다.

## 실패·확장 한계

정상 빈 테이블은 200과 빈 items/0건 통계를 반환한다. 다음 경우는 일부
목록·통계와 metadata를 반환하지 않고 일반 안내의 503으로 처리한다.

```json
{
  "detail": "스캔 이력을 조회하지 못했습니다. 잠시 후 다시 시도해 주세요.",
  "error_code": "SCAN_HISTORY_INCOMPLETE"
}
```

- SCAN_HISTORY_DISABLED: DB 조회 비활성.
- SCAN_HISTORY_READ_FAILED: SDK 실패·잘못된 페이지·변환 실패.
- SCAN_HISTORY_INCOMPLETE: 시간·페이지·평가 상한, 반복 키, 동일 ID 내용 충돌,
  필터 일치 기록의 저장 시각 누락·해석 실패.

상한에 정확히 도달한 마지막 페이지에 다음 키가 없고 시간이 남으면 성공할
수 있다. 내부 예외·테이블 이름·자격증명을 응답에 넣지 않는다. 관리자 인증의
기존 401/403과 서버 키 미구성 시 detail만 있는 503은 그대로 유지한다.

큰 테이블에서는 limit이 작아도 전체 순회 비용 때문에 503이 발생할 수 있다.
시간순 정렬 키와 조회용 파티션이 있는 검증된 인덱스가 필요하다. 예를 들어
모든 이력의 시간 정렬용 파티션/정렬 키와 상태별 시간 정렬용 키를 설계하고,
동일 시각은 scan_id를 정렬 키에 포함해야 한다. 단일 전역 파티션의 쓰기
집중도 고려해야 한다. 시간 버킷이나 샤딩이면 버킷·샤드 간 최신 집합 병합이
필요하다. GSI는 최종 일관성이라는 별도 한계가 있다. 인덱스 정의·운영 존재·
투영 필드·과거 데이터 반영을 확인한 후 Query로 전환해야 하며 이번에는
인덱스나 쓰기 스키마를 생성·수정하지 않는다.

검증은 `test_scan_history_reads.py`의 mock DynamoDB, 가짜 monotonic 시계와
실제 API 직렬화로 수행한다. 기존 포함 URL 이력·직접 URL 복구·인증 테스트도
유지한다. 운영 테이블·인덱스·성능과 Python 3.12 런타임 실행은 별도 확인이다.
