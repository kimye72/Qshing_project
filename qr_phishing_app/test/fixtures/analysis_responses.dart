// Offline API fixtures: no HTTP client, camera or real URL is used.
Map<String, dynamic> analysisResponse({String qrType = 'url'}) => {
  'qr_type': qrType,
  'raw_content_preview': qrType == 'url'
      ? 'https://example.invalid/Path'
      : 'QR 내용',
  'contains_url': qrType == 'url',
  'url': qrType == 'url' ? 'https://example.invalid/Path' : null,
  'risk_score': 10,
  'final_score': 10,
  'status': 'safe',
  'message': '현재 기준으로는 비교적 안전한 URL입니다.',
  'reasons': ['특별한 위험 요소가 발견되지 않았습니다.'],
  'ruleset_version': '1.2',
  'vt_available': false,
  'vt_malicious': 0,
  'vt_suspicious': 0,
  'embedded_url_count': 0,
  'analyzed_embedded_url_count': 0,
  'embedded_url_results': <Map<String, dynamic>>[],
  'embedded_url_failures': <Map<String, dynamic>>[],
  'embedded_url_analysis_complete': true,
};

Map<String, dynamic> embeddedResponse({
  String url = 'https://example.invalid/Path',
  bool available = false,
}) => {
  'url': url,
  'original_url': url,
  'original_candidates': <String>[],
  'analysis_url': url,
  'assumed_https': false,
  'risk_score': 10,
  'final_score': 10,
  'status': 'safe',
  'reasons': ['URL의 구조를 확인했습니다.'],
  'ruleset_version': '1.2',
  'vt_available': available,
  'vt_source': available ? 'url_report' : null,
  'vt_lookup_status': available ? 'available' : null,
  'vt_malicious': 0,
  'vt_suspicious': 0,
};

// Matches the public backend contract; these are reports retrieved this request,
// not reports whose underlying analysis necessarily happened this request.
Map<String, dynamic> requestedReport({bool revalidated = false}) => {
  'vt_available': true,
  'vt_lookup_status': 'available',
  'vt_source': 'url_report',
  'vt_malicious': 0,
  'vt_suspicious': 0,
  'cache_hit': false,
  'cache_revalidated': revalidated,
  'revalidation_reason': revalidated ? 'stale_cache' : 'cache_miss',
};

Map<String, dynamic> cachedReport() => {
  ...requestedReport(),
  'vt_source': 'cached_report',
  'vt_lookup_status': 'cached',
  'cache_hit': true,
  'revalidation_reason': null,
};

Map<String, dynamic> historicalReport({String status = 'timeout'}) => {
  ...cachedReport(),
  'vt_available': false,
  'vt_lookup_status': status,
  'vt_malicious': 3,
  'vt_suspicious': 2,
  'cache_hit': false,
  'revalidation_reason': 'stale_cache',
  'analysis_flags': {'historical_reputation_used': true},
};

Map<String, dynamic> withEmbeddedUrls(List<Map<String, dynamic>> urls) => {
  ...analysisResponse(qrType: 'text_with_url'),
  'contains_url': true,
  'embedded_url_results': urls,
  'embedded_url_count': urls.length,
  'analyzed_embedded_url_count': urls.length,
};
