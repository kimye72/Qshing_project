import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:qr_phishing_app/analysis_result.dart';

import 'fixtures/analysis_responses.dart';

void main() {
  test('UTF-8 JSON preserves backend score/status and nested URL metadata', () {
    final json = withEmbeddedUrls([
      {
        ...embeddedResponse(url: 'https://example.invalid/Path?Token=AbC'),
        'original_url': 'Example.invalid/Path?Token=AbC',
        'original_candidates': ['Example.invalid/Path?Token=AbC'],
        'assumed_https': true,
      },
    ])..addAll({'risk_score': 85, 'status': 'danger'});
    final result = AnalysisResult.fromBodyBytes(utf8.encode(jsonEncode(json)));
    expect(result.riskScore, 85);
    expect(result.status, 'danger');
    final child = result.embeddedUrls.single;
    expect(child.score, 10);
    expect(child.analysisUrl, 'https://example.invalid/Path?Token=AbC');
    expect(child.originalCandidates, ['Example.invalid/Path?Token=AbC']);
    expect(child.assumedHttps, isTrue);
  });

  test('available, unavailable and missing reputation remain distinct', () {
    final json = analysisResponse();
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.unavailable,
    );
    json['vt_available'] = true;
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.available,
    );
    json.remove('vt_available');
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.unknown,
    );
    for (final invalid in [null, 'true', 1]) {
      json['vt_available'] = invalid;
      expect(
        AnalysisResult.fromJson(json).reputation.availability,
        ReputationAvailability.unknown,
      );
    }
  });

  test('missing VT counts are not interpreted as zero detections', () {
    final json = analysisResponse()..['vt_available'] = true;
    json.remove('vt_malicious');
    json.remove('vt_suspicious');
    final reputation = AnalysisResult.fromJson(json).reputation;
    expect(reputation.malicious, isNull);
    expect(reputation.suspicious, isNull);
  });

  test('child reputation does not inherit parent or sibling VT fields', () {
    final missing = embeddedResponse()..remove('vt_available');
    final result = AnalysisResult.fromJson(
      withEmbeddedUrls([
        embeddedResponse(available: true),
        embeddedResponse(),
        missing,
      ])..['vt_available'] = true,
    );
    expect(result.embeddedUrls.map((item) => item.reputation.availability), [
      ReputationAvailability.available,
      ReputationAvailability.unavailable,
      ReputationAvailability.unknown,
    ]);
    expect(result.showParentReputation, isFalse);
  });

  test('URL-free QR types do not need reputation notices', () {
    for (final type in [
      'phone',
      'phone_text',
      'wifi',
      'text',
      'sms',
      'email',
    ]) {
      final json = analysisResponse(qrType: type);
      // Recipients, subjects and SSIDs may appear in public extraction fields.
      json['extracted_urls'] = ['https://subject.invalid'];
      json['contains_url'] = true;
      expect(
        AnalysisResult.fromJson(json).showParentReputation,
        isFalse,
        reason: type,
      );
    }
  });

  test('legacy URL-bearing text shows its unknown parent lookup state', () {
    final json = analysisResponse(qrType: 'text_with_url')
      ..['contains_url'] = true
      ..remove('vt_available')
      ..remove('embedded_url_analysis_complete');
    final result = AnalysisResult.fromJson(json);
    expect(result.showParentReputation, isTrue);
    expect(result.embeddedAnalysisComplete, isNull);
    expect(result.reputation.availability, ReputationAvailability.unknown);
  });

  test('failure and skipped counts use separate response fields', () {
    final json = withEmbeddedUrls([embeddedResponse()])
      ..addAll({
        'embedded_url_count': 5,
        'embedded_url_analysis_complete': false,
        'analysis_flags': {'embedded_url_skipped_count': 2},
        'embedded_url_failures': [
          {
            'analysis_url': 'https://failed.invalid',
            'error_code': 'EMBEDDED_URL_ANALYSIS_FAILED',
            'error': 'Traceback secret-key',
          },
        ],
      });
    final result = AnalysisResult.fromJson(json);
    expect(result.isIncomplete, isTrue);
    expect(result.skippedEmbeddedUrlCount, 2);
    expect(
      result.embeddedFailures.single.analysisUrl,
      'https://failed.invalid',
    );
    expect(
      result.embeddedFailures.single.errorCode,
      'EMBEDDED_URL_ANALYSIS_FAILED',
    );
    expect(result.embeddedUrls.single.score, 10);
  });

  test('legacy missing optional lists do not break core result parsing', () {
    final json = analysisResponse();
    for (final key in [
      'embedded_url_results',
      'embedded_url_failures',
      'embedded_url_count',
      'analyzed_embedded_url_count',
      'embedded_url_analysis_complete',
    ]) {
      json.remove(key);
    }
    final result = AnalysisResult.fromJson(json);
    expect(result.riskScore, 10);
    expect(result.embeddedUrls, isEmpty);
    expect(result.embeddedAnalysisComplete, isNull);
    expect(result.skippedEmbeddedUrlCount, isNull);
  });

  test(
    'developer VT details become generic user reasons for parent and child',
    () {
      const reason = 'VirusTotal 조회 결과 미사용: .env VIRUSTOTAL_API_KEY=secret';
      final result = AnalysisResult.fromJson(
        withEmbeddedUrls([
          embeddedResponse()..['reasons'] = [reason],
        ])..['reasons'] = [reason],
      );
      for (final reasons in [
        result.reasons,
        result.embeddedUrls.single.reasons,
      ]) {
        expect(reasons.join(), isNot(contains('VIRUSTOTAL_API_KEY')));
        expect(reasons.join(), isNot(contains('secret')));
      }
      expect(riskStatusLabel(result.status), '낮은 위험');
      expect(result.displayMessage, isNot(contains('비교적 안전한')));
    },
  );

  test('invalid core response still fails with FormatException', () {
    for (final bytes in [
      utf8.encode('[]'),
      utf8.encode('{bad json'),
      utf8.encode(jsonEncode(analysisResponse()..['status'] = 'unknown')),
      utf8.encode(jsonEncode(analysisResponse()..['risk_score'] = '10')),
    ]) {
      expect(() => AnalysisResult.fromBodyBytes(bytes), throwsFormatException);
    }
  });
}
