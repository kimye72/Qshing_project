import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_phishing_app/analysis_result.dart';
import 'package:qr_phishing_app/main.dart';

import 'fixtures/analysis_responses.dart';

Future<void> showResult(
  WidgetTester tester,
  Map<String, dynamic> json, {
  VoidCallback? onRescan,
  double textScale = 1,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: AppColors.accent),
      home: Scaffold(
        body: MediaQuery(
          data: MediaQueryData(textScaler: TextScaler.linear(textScale)),
          child: SizedBox(
            height: 240,
            child: AnalysisResultView(
              result: AnalysisResult.fromJson(json),
              onRescan: onRescan ?? () {},
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Finder textContaining(String text) =>
    find.textContaining(text, findRichText: true);

void main() {
  // Widget tests construct response fixtures directly. ScanPage is never
  // mounted, so the camera and analysis API cannot be invoked.
  testWidgets(
    'safe means low risk; missing reputation has its own explanation',
    (tester) async {
      await showResult(tester, analysisResponse());
      expect(find.text('낮은 위험'), findsOneWidget);
      expect(find.text('위험 점수 10'), findsOneWidget);
      expect(find.text('안전'), findsNothing);
      expect(textContaining('비교적 안전한 URL'), findsNothing);
      expect(textContaining('외부 평판 정보 없음'), findsOneWidget);
      expect(textContaining('현재 확인한 정보만으로 평가한 결과입니다.'), findsOneWidget);
      expect(textContaining('악성 탐지 0건'), findsNothing);
    },
  );

  testWidgets(
    'available report with zero malicious count differs from missing report',
    (tester) async {
      await showResult(tester, analysisResponse()..['vt_available'] = true);
      expect(textContaining('외부 평판 정보 있음'), findsOneWidget);
      expect(textContaining('악성 탐지 0건'), findsOneWidget);
      expect(textContaining('외부 평판 정보 없음'), findsNothing);
      expect(textContaining('안전성을 보장하지 않습니다.'), findsWidgets);
    },
  );

  testWidgets('suspicious detections remain visible when malicious is zero', (
    tester,
  ) async {
    await showResult(
      tester,
      analysisResponse()..addAll({
        'vt_available': true,
        'vt_malicious': 0,
        'vt_suspicious': 2,
        'risk_score': 55,
        'status': 'warning',
      }),
    );
    expect(textContaining('악성 탐지 0건'), findsOneWidget);
    expect(textContaining('의심 탐지 2건'), findsOneWidget);
    expect(find.text('주의'), findsOneWidget);
    expect(find.text('위험 점수 55'), findsOneWidget);
  });

  testWidgets(
    'missing old VT fields show unknown rather than successful lookup',
    (tester) async {
      final json = analysisResponse()..remove('vt_available');
      await showResult(tester, json);
      expect(textContaining('조회 상태 확인 불가'), findsOneWidget);
      expect(textContaining('외부 평판 정보 있음'), findsNothing);
      expect(textContaining('외부 평판 정보 없음'), findsNothing);
      expect(textContaining('악성 탐지 0건'), findsNothing);
      json['vt_available'] = true;
      json.remove('vt_malicious');
      await showResult(tester, json);
      expect(textContaining('악성 탐지 수 확인 불가'), findsOneWidget);
      expect(textContaining('악성 탐지 0건'), findsNothing);
    },
  );

  testWidgets(
    'URL-free phone Wi-Fi and text do not display missing-reputation notice',
    (tester) async {
      for (final type in [
        'phone',
        'phone_text',
        'wifi',
        'text',
        'sms',
        'email',
      ]) {
        await showResult(tester, analysisResponse(qrType: type));
        expect(textContaining('외부 평판 정보 없음'), findsNothing, reason: type);
        expect(textContaining('조회 상태 확인 불가'), findsNothing, reason: type);
      }
    },
  );

  testWidgets(
    'embedded links each show score, reasons and independent reputation',
    (tester) async {
      final urls = [
        embeddedResponse(url: 'https://one.invalid/Path', available: true),
        embeddedResponse(url: 'https://two.invalid/Path')..addAll({
          'final_score': 75,
          'status': 'danger',
          'reasons': ['두 번째 링크의 위험 신호'],
        }),
        embeddedResponse(url: 'https://three.invalid/Path')
          ..remove('vt_available'),
      ];
      await showResult(
        tester,
        withEmbeddedUrls(urls)..addAll({
          'vt_available': true,
          'vt_malicious': 0,
          'risk_score': 75,
          'status': 'danger',
        }),
      );
      for (var index = 0; index < urls.length; index++) {
        final card = find.byKey(ValueKey('embedded-result-$index'));
        expect(
          find.descendant(
            of: card,
            matching: find.text(urls[index]['analysis_url'] as String),
          ),
          findsOneWidget,
        );
      }
      expect(textContaining('외부 평판 정보 있음'), findsOneWidget);
      expect(textContaining('외부 평판 정보 없음'), findsOneWidget);
      expect(textContaining('조회 상태 확인 불가'), findsOneWidget);
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('embedded-result-1')),
          matching: find.text('위험 점수 75'),
        ),
        findsOneWidget,
      );
      expect(find.text('두 번째 링크의 위험 신호'), findsOneWidget);
      expect(textContaining('VirusTotal 평판 검사 포함'), findsNothing);
    },
  );

  testWidgets(
    'assumed HTTPS keeps original candidate separate from analysis address',
    (tester) async {
      await showResult(
        tester,
        withEmbeddedUrls([
          embeddedResponse()..addAll({
            'assumed_https': true,
            'original_url': 'Example.invalid/Path',
            'original_candidates': ['Example.invalid/Path'],
          }),
        ]),
      );
      expect(find.text('원본 후보'), findsOneWidget);
      expect(find.text('Example.invalid/Path'), findsOneWidget);
      expect(find.text('https://example.invalid/Path'), findsOneWidget);
      expect(
        textContaining('분석을 위해 HTTPS를 가정했습니다. 실제 HTTPS 지원 여부는 확인하지 않았습니다.'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'partial failure keeps successful results and shows a top warning',
    (tester) async {
      final json = withEmbeddedUrls([embeddedResponse()])
        ..addAll({
          'risk_score': 55,
          'status': 'warning',
          'embedded_url_analysis_complete': false,
          'embedded_url_count': 2,
          'analysis_flags': {'embedded_url_skipped_count': 0},
          'embedded_url_failures': [
            {
              'original_url': 'failed.invalid/Path',
              'original_candidates': ['failed.invalid/Path'],
              'analysis_url': 'https://failed.invalid/Path',
              'assumed_https': true,
              'error_code': 'EMBEDDED_URL_ANALYSIS_FAILED',
              'error': 'Traceback secret-key VIRUSTOTAL_API_KEY',
            },
          ],
        });
      await showResult(tester, json);
      expect(find.text('일부 링크의 분석을 완료하지 못했습니다.'), findsOneWidget);
      expect(find.byIcon(Icons.warning_rounded), findsWidgets);
      expect(
        tester.getTopLeft(find.text('일부 링크의 분석을 완료하지 못했습니다.')).dy,
        lessThan(tester.getTopLeft(find.text('위험 점수 55')).dy),
      );
      expect(find.byKey(const ValueKey('embedded-result-0')), findsOneWidget);
      expect(find.text('https://failed.invalid/Path'), findsOneWidget);
      expect(textContaining('1개 링크의 분석에 실패했습니다.'), findsOneWidget);
      expect(textContaining('분석 개수 제한'), findsNothing);
      expect(textContaining('secret-key'), findsNothing);
      expect(textContaining('VIRUSTOTAL_API_KEY'), findsNothing);
    },
  );

  testWidgets('limit exclusions are distinguished from analysis failures', (
    tester,
  ) async {
    await showResult(
      tester,
      withEmbeddedUrls([
        embeddedResponse(url: 'https://one.invalid'),
        embeddedResponse(url: 'https://two.invalid'),
        embeddedResponse(url: 'https://three.invalid'),
      ])..addAll({
        'embedded_url_count': 5,
        'embedded_url_analysis_complete': false,
        'analysis_flags': {'embedded_url_skipped_count': 2},
      }),
    );
    expect(find.text('일부 링크의 분석을 완료하지 못했습니다.'), findsOneWidget);
    expect(textContaining('분석 개수 제한으로 2개 링크를 검사하지 못했습니다.'), findsOneWidget);
    expect(textContaining('분석에 실패했습니다.'), findsNothing);
    expect(find.text('포함 링크 5개 중 3개 분석 완료'), findsOneWidget);
    expect(find.text('분석하지 못한 링크'), findsNothing);
  });

  testWidgets(
    'incomplete old response does not invent a failure or limit reason',
    (tester) async {
      await showResult(
        tester,
        analysisResponse()
          ..addAll({'embedded_url_analysis_complete': false})
          ..remove('embedded_url_failures'),
      );
      expect(find.text('일부 링크의 분석을 완료하지 못했습니다.'), findsOneWidget);
      expect(textContaining('미완료 사유의 상세 정보가 없습니다.'), findsOneWidget);
      expect(textContaining('분석 개수 제한'), findsNothing);
    },
  );

  testWidgets('cached report is not presented as a fresh successful lookup', (
    tester,
  ) async {
    await showResult(
      tester,
      analysisResponse()..addAll({'vt_available': true, 'cache_hit': true}),
    );
    expect(textContaining('저장된 평판 정보이며 최신 상태와 다를 수 있습니다.'), findsOneWidget);
  });

  testWidgets('legacy developer reason is sanitized on screen', (tester) async {
    await showResult(
      tester,
      analysisResponse()
        ..['reasons'] = [
          'VirusTotal 조회 결과 미사용: .env에서 VIRUSTOTAL_API_KEY=secret 설정하세요.',
        ],
    );
    expect(textContaining('secret'), findsNothing);
    expect(textContaining('.env'), findsNothing);
    expect(textContaining('해당 정보는 점수에 반영하지 않았습니다.'), findsOneWidget);
  });

  testWidgets(
    'small panel and large text wrap long addresses and keep rescan reachable',
    (tester) async {
      tester.view.physicalSize = const Size(280, 568);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      var rescans = 0;
      final longUrl =
          'https://example.invalid/${'LongPath' * 40}?Token=${'AbC' * 100}';
      await showResult(
        tester,
        withEmbeddedUrls([
          embeddedResponse(url: longUrl)
            ..['reasons'] = ['긴 사유 ${'위험 신호를 확인했습니다. ' * 40}'],
        ]),
        textScale: 1.8,
        onRescan: () => rescans++,
      );
      expect(tester.takeException(), isNull);
      expect(find.text(longUrl), findsOneWidget);
      expect(find.byKey(const Key('analysis-result-scroll')), findsOneWidget);
      final button = find.widgetWithText(FilledButton, '다시 스캔하기');
      await tester.ensureVisible(button);
      await tester.pumpAndSettle();
      await tester.tap(button);
      await tester.pump();
      expect(rescans, 1);
      expect(tester.takeException(), isNull);
      expect(find.byType(FilledButton), findsOneWidget);
      expect(find.text('링크 열기'), findsNothing);
    },
  );
}
