import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_phishing_app/main.dart';
import 'package:qr_phishing_app/result_actions.dart';

import 'fixtures/analysis_responses.dart';

// Exercise the real MobileScanner widget/controller against a fake platform.
// No method channel, hardware, API or external address is contacted.
class FakeCamera extends MobileScannerPlatform {
  final captures = StreamController<BarcodeCapture?>.broadcast();
  final torch = StreamController<TorchState>.broadcast();
  final zoom = StreamController<double>.broadcast();
  Completer<void>? startGate;
  MobileScannerException? nextStartError;
  int starts = 0;
  int stops = 0;
  int disposals = 0;
  int activeOperations = 0;
  int maxActiveOperations = 0;
  int barcodeListeners = 0;
  int peakBarcodeListeners = 0;

  @override
  Stream<BarcodeCapture?> get barcodesStream => Stream.multi((sink) {
    barcodeListeners++;
    if (barcodeListeners > peakBarcodeListeners) {
      peakBarcodeListeners = barcodeListeners;
    }
    final subscription = captures.stream.listen(
      sink.add,
      onError: sink.addError,
      onDone: sink.close,
    );
    sink.onCancel = () {
      barcodeListeners--;
      return subscription.cancel();
    };
  }, isBroadcast: true);

  @override
  Stream<TorchState> get torchStateStream => torch.stream;
  @override
  Stream<double> get zoomScaleStateStream => zoom.stream;

  void _enter() {
    activeOperations++;
    if (activeOperations > maxActiveOperations) {
      maxActiveOperations = activeOperations;
    }
  }

  @override
  Future<MobileScannerViewAttributes> start(StartOptions options) async {
    starts++;
    _enter();
    try {
      final gate = startGate;
      startGate = null;
      if (gate != null) await gate.future;
      final error = nextStartError;
      nextStartError = null;
      if (error != null) throw error;
      return const MobileScannerViewAttributes(
        cameraDirection: CameraFacing.back,
        currentTorchMode: TorchState.off,
        size: Size(640, 480),
        initialDeviceOrientation: DeviceOrientation.portraitUp,
      );
    } finally {
      activeOperations--;
    }
  }

  @override
  Future<void> stop() async {
    stops++;
    _enter();
    activeOperations--;
  }

  @override
  Widget buildCameraView() =>
      const ColoredBox(color: Colors.black, key: Key('fake-preview'));

  @override
  Future<void> dispose() async {
    disposals++;
  }

  void detect(String content) =>
      captures.add(BarcodeCapture(barcodes: [Barcode(rawValue: content)]));

  Future<void> close() async {
    await captures.close();
    await torch.close();
    await zoom.close();
  }
}

class FakeAnalysisClient extends http.BaseClient {
  final requests = <http.Request>[];
  final responses = <Completer<http.StreamedResponse>>[];
  bool closed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    requests.add(request as http.Request);
    final response = Completer<http.StreamedResponse>();
    responses.add(response);
    return response.future;
  }

  void complete(int index, {Map<String, dynamic>? json, int status = 200}) {
    responses[index].complete(
      http.StreamedResponse(
        Stream.value(utf8.encode(jsonEncode(json ?? analysisResponse()))),
        status,
      ),
    );
  }

  @override
  void close() {
    closed = true;
  }
}

class FakeExternalLauncher implements ExternalAppLauncher {
  final addresses = <String>[];
  Completer<bool>? gate;
  bool succeeds = true;
  bool throwsError = false;

  @override
  Future<bool> open(String address) async {
    addresses.add(address);
    if (throwsError) throw StateError('secret platform exception');
    return gate == null ? succeeds : await gate!.future;
  }
}

// A pulsing scanning frame intentionally animates continuously. Advance a few
// frames instead of pumpAndSettle, which would wait forever in scanning state.
Future<void> frames(WidgetTester tester) async {
  for (var index = 0; index < 5; index++) {
    await tester.pump(const Duration(milliseconds: 20));
  }
}

Future<void> background(WidgetTester tester) async {
  for (final state in [
    AppLifecycleState.inactive,
    AppLifecycleState.hidden,
    AppLifecycleState.paused,
  ]) {
    tester.binding.handleAppLifecycleStateChanged(state);
    await frames(tester);
  }
}

Future<void> resume(WidgetTester tester) async {
  for (final state in [
    AppLifecycleState.hidden,
    AppLifecycleState.inactive,
    AppLifecycleState.resumed,
  ]) {
    tester.binding.handleAppLifecycleStateChanged(state);
    await frames(tester);
  }
}

Future<void> mountPage(
  WidgetTester tester,
  FakeAnalysisClient client, {
  double scale = 1,
  bool disableAnimations = false,
  EdgeInsets safePadding = EdgeInsets.zero,
  ExternalAppLauncher launcher = const SystemExternalAppLauncher(),
  String endpoint = 'https://analysis.invalid/analyze-qr',
}) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: AppColors.accent),
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(
          textScaler: TextScaler.linear(scale),
          disableAnimations: disableAnimations,
          padding: safePadding,
        ),
        child: child!,
      ),
      home: ScanPage(client: client, apiUrl: endpoint, launcher: launcher),
    ),
  );
  await frames(tester);
}

void main() {
  late FakeCamera camera;
  late FakeAnalysisClient client;
  late FakeExternalLauncher launcher;
  late MobileScannerPlatform originalPlatform;

  setUp(() {
    TestWidgetsFlutterBinding.ensureInitialized()
        .handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    originalPlatform = MobileScannerPlatform.instance;
    camera = FakeCamera();
    client = FakeAnalysisClient();
    launcher = FakeExternalLauncher();
    MobileScannerPlatform.instance = camera;
  });

  tearDown(() async {
    await camera.close();
    MobileScannerPlatform.instance = originalPlatform;
  });

  Future<void> analyze(
    WidgetTester tester,
    String content,
    Map<String, dynamic> json,
  ) async {
    camera.detect(content);
    await frames(tester);
    client.complete(client.requests.length - 1, json: json);
    await frames(tester);
  }

  Future<void> press(WidgetTester tester, String key) async {
    final button = find.byKey(ValueKey(key));
    await tester.ensureVisible(button);
    await frames(tester);
    await tester.tap(button);
    await tester.pumpAndSettle();
  }

  testWidgets(
    'unsupported addresses and incomplete child metadata have no action',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      for (final address in [
        'javascript:alert(1)',
        'data:text/plain,hello',
        'file:///tmp/a',
        'intent://example.invalid',
        'https://user@example.invalid',
        'https://@example.invalid',
        '',
      ]) {
        await analyze(tester, 'QR', analysisResponse()..['url'] = address);
        expect(find.byKey(const Key('open-direct-url')), findsNothing);
        await tester.tap(find.byKey(const Key('rescan-button')));
        await frames(tester);
      }
      await analyze(
        tester,
        '본문',
        withEmbeddedUrls([
          embeddedResponse()..addAll({'risk_score': null, 'final_score': null}),
          embeddedResponse()..['status'] = null,
          embeddedResponse()..['analysis_url'] = 'https://user@child.invalid',
        ]),
      );
      for (var index = 0; index < 3; index++) {
        expect(find.byKey(ValueKey('open-embedded-$index')), findsNothing);
      }
      expect(launcher.addresses, isEmpty);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'direct link confirms exact address, cancels, and blocks repeated clicks',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      const address =
          'https://example.invalid/a/../AbC?Token=Ab%2fCd&x=%26%3D%3F%2B';
      await analyze(
        tester,
        address,
        analysisResponse()..addAll({
          'url': address,
          'status': 'warning',
          'risk_score': 55,
          'embedded_url_analysis_complete': false,
        }),
      );
      expect(launcher.addresses, isEmpty);
      await press(tester, 'open-direct-url');
      expect(find.text('실행할 주소'), findsOneWidget);
      expect(find.byKey(const Key('action-link-address')), findsOneWidget);
      expect(find.text(address), findsWidgets);
      expect(find.textContaining('주의 판정입니다.'), findsOneWidget);
      expect(find.textContaining('일부 링크의 분석을 완료하지 못했습니다.'), findsNWidgets(2));
      expect(find.textContaining('외부 평판 정보 없음'), findsNWidgets(2));
      expect(launcher.addresses, isEmpty);
      await press(tester, 'action-cancel');
      expect(find.text('실행을 취소했습니다.'), findsOneWidget);
      expect(find.byType(AnalysisResultView), findsOneWidget);
      final button = tester.widget<OutlinedButton>(
        find.byKey(const Key('open-direct-url')),
      );
      button.onPressed!();
      button.onPressed!();
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsOneWidget);
      final confirm = tester
          .widget<TextButton>(find.byKey(const Key('action-confirm')))
          .onPressed!;
      confirm();
      confirm();
      await tester.pumpAndSettle();
      expect(launcher.addresses, [address]);
      await background(tester);
      await resume(tester);
      expect(find.byType(AnalysisResultView), findsOneWidget);
      expect(find.text('Qshing'), findsOneWidget);
      expect(camera.starts, 1);
      expect(find.byType(MobileScanner), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'each embedded link confirms its own target, assumptions and reputation',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      final json =
          withEmbeddedUrls([
            embeddedResponse(url: 'https://assumed.invalid/Path?A=B')..addAll({
              ...requestedReport(),
              'assumed_https': true,
              'original_candidates': ['assumed.invalid/Path?A=B'],
            }),
            embeddedResponse(url: 'https://past.invalid/Other')
              ..addAll(historicalReport()),
            embeddedResponse(url: 'https://blocked.invalid')
              ..addAll({'status': 'danger', 'final_score': 85}),
          ])..addAll({
            'url': 'https://parent.invalid',
            'status': 'warning',
            'risk_score': 55,
            'embedded_url_analysis_complete': false,
            'analysis_flags': {'embedded_url_skipped_count': 2},
            'embedded_url_failures': [
              {
                'analysis_url': 'https://failed.invalid',
                'error_code': 'EMBEDDED_URL_ANALYSIS_FAILED',
              },
            ],
          });
      await analyze(tester, '문자 안 링크', json);
      expect(find.byKey(const Key('open-direct-url')), findsNothing);
      await press(tester, 'open-embedded-0');
      final dialog = find.byType(AlertDialog);
      expect(
        find.descendant(
          of: dialog,
          matching: find.text('https://assumed.invalid/Path?A=B'),
        ),
        findsOneWidget,
      );
      expect(
        find.descendant(
          of: dialog,
          matching: find.textContaining('실제 HTTPS 지원 여부는 확인하지 않았습니다.'),
        ),
        findsOneWidget,
      );
      expect(
        find.descendant(
          of: dialog,
          matching: find.textContaining('이번 요청에서 외부 리포트를 조회했습니다.'),
        ),
        findsOneWidget,
      );
      expect(
        find.descendant(of: dialog, matching: find.textContaining('과거 악성 탐지')),
        findsNothing,
      );
      expect(
        find.descendant(
          of: dialog,
          matching: find.textContaining('분석 개수 제한으로 2개'),
        ),
        findsOneWidget,
      );
      await press(tester, 'action-confirm');
      await press(tester, 'open-embedded-1');
      expect(
        find.descendant(
          of: find.byType(AlertDialog),
          matching: find.textContaining('점수에 과거 평판 정보를 사용'),
        ),
        findsOneWidget,
      );
      expect(
        find.descendant(
          of: find.byType(AlertDialog),
          matching: find.textContaining('과거 악성 탐지 3건'),
        ),
        findsOneWidget,
      );
      await press(tester, 'action-confirm');
      expect(launcher.addresses, [
        'https://assumed.invalid/Path?A=B',
        'https://past.invalid/Other',
      ]);
      expect(
        tester
            .widget<OutlinedButton>(find.byKey(const Key('open-embedded-2')))
            .onPressed,
        isNull,
      );
      expect(find.text('위험 판정으로 링크 열기를 제한했습니다.'), findsOneWidget);
      final failure = find.byKey(const ValueKey('embedded-failure-0'));
      expect(
        find.descendant(of: failure, matching: find.byType(OutlinedButton)),
        findsNothing,
      );
    },
  );

  testWidgets(
    'Unicode path and port candidates launch the complete child analysis address',
    (tester) async {
      const candidates = [
        'example.com/배송조회?token=AbC',
        'example.com/track?next=배송조회',
        'example.com:8443/배송조회?Token=Ab%26Cd+E#조각%23',
      ];
      await mountPage(tester, client, launcher: launcher);
      await analyze(
        tester,
        '배송 확인: ${candidates.join(' ')}',
        withEmbeddedUrls([
          for (final candidate in candidates)
            embeddedResponse(url: 'https://$candidate')..addAll({
              // Neither a parent's representative URL nor a truncated legacy
              // url field is an execution target when analysis_url is present.
              'url': 'https://example.com/',
              'original_url': candidate,
              'original_candidates': [candidate],
              'assumed_https': true,
            }),
        ])..['url'] = 'https://parent.invalid/',
      );
      for (var index = 0; index < candidates.length; index++) {
        await press(tester, 'open-embedded-$index');
        final dialog = find.byType(AlertDialog);
        expect(
          find.descendant(
            of: dialog,
            matching: find.text('https://${candidates[index]}'),
          ),
          findsOneWidget,
        );
        expect(
          find.descendant(
            of: dialog,
            matching: find.textContaining('HTTPS를 가정'),
          ),
          findsWidgets,
        );
        await press(tester, 'action-confirm');
        expect(launcher.addresses.last, 'https://${candidates[index]}');
      }
      expect(launcher.addresses, [
        for (final candidate in candidates) 'https://$candidate',
      ]);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'danger parent blocks direct and all embedded links and SMS composing',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      for (final type in ['url', 'text_with_url', 'sms']) {
        final json = type == 'text_with_url'
            ? withEmbeddedUrls([embeddedResponse()])
            : analysisResponse(qrType: type);
        json.addAll({'status': 'danger', 'risk_score': 85});
        await analyze(tester, 'SMSTO:01012345678:본문', json);
        final key = type == 'url'
            ? 'open-direct-url'
            : type == 'sms'
            ? 'compose-sms'
            : 'open-embedded-0';
        expect(
          tester.widget<OutlinedButton>(find.byKey(ValueKey(key))).onPressed,
          isNull,
        );
        expect(
          find.text(
            type == 'sms' ? '위험 판정으로 문자 작성을 제한했습니다.' : '위험 판정으로 링크 열기를 제한했습니다.',
          ),
          findsOneWidget,
        );
        await tester.tap(find.byKey(const Key('rescan-button')));
        await frames(tester);
      }
      expect(launcher.addresses, isEmpty);
    },
  );

  testWidgets(
    'SMS action uses only session QR, preserves each form and never sends',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      const body = '한글 & ? = + https://example.invalid/?A=B&C=D+E';
      final cases = [
        'SMS:%2B821012345678?subject=제목:콜론&body=${Uri.encodeComponent(body)}',
        'SMSTO:+821012345678:${Uri.encodeComponent(body)}',
        'sms:+821012345678:$body',
        'sms:+821012345678?body=&subject=제목:콜론',
      ];
      for (var index = 0; index < cases.length; index++) {
        await analyze(
          tester,
          cases[index],
          analysisResponse(qrType: 'sms')..addAll({
            'status': 'warning',
            'risk_score': 55,
            'raw_content_preview': 'SMS:010****9999:마스킹된 미리보기',
            'structured_content': {
              'sms_recipient_masked': '010****9999',
              'sms_body_preview': '미리보기',
            },
            'embedded_url_analysis_complete': false,
          }),
        );
        expect(launcher.addresses, hasLength(index));
        await press(tester, 'compose-sms');
        expect(find.text('+821012345678'), findsOneWidget);
        expect(find.text(index == 3 ? '(본문 없음)' : body), findsOneWidget);
        expect(find.textContaining('전송은 문자 앱에서 직접 진행'), findsOneWidget);
        expect(find.textContaining('주의 판정입니다.'), findsOneWidget);
        expect(
          find.descendant(
            of: find.byType(AlertDialog),
            matching: find.textContaining('일부 링크의 분석'),
          ),
          findsOneWidget,
        );
        await press(tester, 'action-confirm');
        final address = launcher.addresses.last;
        expect(address.startsWith('sms:+821012345678?body='), isTrue);
        expect(
          Uri.decodeComponent(address.split('?body=')[1]),
          index == 3 ? '' : body,
        );
        await tester.tap(find.byKey(const Key('rescan-button')));
        await frames(tester);
      }
      await analyze(
        tester,
        'sms:010****9999:본문',
        analysisResponse(qrType: 'sms'),
      );
      expect(find.byKey(const Key('compose-sms')), findsNothing);
      expect(find.textContaining('수신 번호 또는 문자 형식을 확인할 수 없어'), findsOneWidget);
      expect(launcher.addresses, hasLength(4));
    },
  );

  testWidgets(
    'rescan dismisses old confirmation and stale callbacks cannot launch',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      await analyze(
        tester,
        'sms:01012345678:old',
        analysisResponse(qrType: 'sms'),
      );
      final oldView = tester.widget<AnalysisResultView>(
        find.byType(AnalysisResultView),
      );
      final reset = tester
          .widget<FilledButton>(find.byKey(const Key('rescan-button')))
          .onPressed!;
      await press(tester, 'compose-sms');
      final oldConfirm = tester
          .widget<TextButton>(find.byKey(const Key('action-confirm')))
          .onPressed!;
      reset();
      oldConfirm();
      await frames(tester);
      expect(find.byType(AlertDialog), findsNothing);
      expect(launcher.addresses, isEmpty);
      await analyze(
        tester,
        'sms:01098765432:new',
        analysisResponse(qrType: 'sms'),
      );
      oldView.onComposeSms!();
      await frames(tester);
      expect(find.byType(AlertDialog), findsNothing);
      await press(tester, 'compose-sms');
      expect(find.text('01098765432'), findsOneWidget);
      expect(find.text('old'), findsNothing);
      await press(tester, 'action-confirm');
      expect(launcher.addresses, ['sms:01098765432?body=new']);
      expect(camera.starts, 2);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'pending OS launch cannot duplicate or affect a new scan on late failure',
    (tester) async {
      launcher.gate = Completer<bool>();
      await mountPage(tester, client, launcher: launcher);
      await analyze(tester, 'QR', analysisResponse());
      final oldView = tester.widget<AnalysisResultView>(
        find.byType(AnalysisResultView),
      );
      await press(tester, 'open-direct-url');
      await press(tester, 'action-confirm');
      oldView.onOpenLink!(LinkActionTarget.direct(oldView.result)!);
      await frames(tester);
      expect(launcher.addresses, hasLength(1));
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      await analyze(
        tester,
        'QR2',
        analysisResponse()..['url'] = 'https://new.invalid/Path',
      );
      expect(
        tester
            .widget<OutlinedButton>(find.byKey(const Key('open-direct-url')))
            .onPressed,
        isNull,
      );
      launcher.gate!.complete(false);
      await frames(tester);
      expect(find.textContaining('외부 앱을 열지 못했습니다.'), findsNothing);
      expect(
        tester
            .widget<OutlinedButton>(find.byKey(const Key('open-direct-url')))
            .onPressed,
        isNotNull,
      );
      oldView.onOpenLink!(LinkActionTarget.direct(oldView.result)!);
      await frames(tester);
      expect(find.byType(AlertDialog), findsNothing);
      expect(launcher.addresses, hasLength(1));
      expect(find.text('https://new.invalid/Path'), findsWidgets);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'launcher false and exception retain result and show only public recovery',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      await analyze(tester, 'QR', analysisResponse());
      for (final throwsError in [false, true]) {
        launcher.succeeds = false;
        launcher.throwsError = throwsError;
        await press(tester, 'open-direct-url');
        await press(tester, 'action-confirm');
        expect(find.textContaining('외부 앱을 열지 못했습니다.'), findsOneWidget);
        expect(find.textContaining('secret'), findsNothing);
        expect(find.byType(AnalysisResultView), findsOneWidget);
        expect(
          find.byKey(const Key('rescan-button')).hitTestable(),
          findsOneWidget,
        );
      }
    },
  );

  testWidgets(
    'dispose removes confirmation and ignores a pending launch completion',
    (tester) async {
      await mountPage(tester, client, launcher: launcher);
      await analyze(tester, 'QR', analysisResponse());
      await press(tester, 'open-direct-url');
      final confirm = tester
          .widget<TextButton>(find.byKey(const Key('action-confirm')))
          .onPressed!;
      await tester.pumpWidget(const SizedBox.shrink());
      confirm();
      await frames(tester);
      expect(launcher.addresses, isEmpty);
      launcher.gate = Completer<bool>();
      await mountPage(tester, client, launcher: launcher);
      await analyze(tester, 'QR', analysisResponse());
      await press(tester, 'open-direct-url');
      await press(tester, 'action-confirm');
      await tester.pumpWidget(const SizedBox.shrink());
      launcher.gate!.complete(false);
      await frames(tester);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'small 2x screen scrolls action confirmations and keeps bottom rescan reachable',
    (tester) async {
      tester.view.physicalSize = const Size(280, 568);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await mountPage(tester, client, launcher: launcher, scale: 2);
      final body = '한글 예약문자 & ? = + 긴 본문 ${'본문 ' * 80}'.trimRight();
      final address =
          'https://example.invalid/${'LongPath' * 40}?Token=${'AbC' * 80}';
      await analyze(
        tester,
        'SMSTO:01012345678:$body',
        withEmbeddedUrls([
          embeddedResponse(url: address)..addAll(historicalReport()),
        ])..addAll({
          'qr_type': 'sms',
          'status': 'warning',
          'risk_score': 55,
          'embedded_url_analysis_complete': false,
        }),
      );
      await press(tester, 'compose-sms');
      expect(
        find.byKey(const Key('action-confirm')).hitTestable(),
        findsOneWidget,
      );
      expect(find.text(body), findsOneWidget);
      expect(tester.takeException(), isNull);
      await press(tester, 'action-cancel');
      expect(
        find.byKey(const Key('rescan-button')).hitTestable(),
        findsOneWidget,
      );
      // Advance the fake clock past transient cancellation feedback. It may
      // overlay the last body card, but never the fixed rescan action.
      await tester.pump(const Duration(seconds: 5));
      await tester.pumpAndSettle();
      await press(tester, 'open-embedded-0');
      expect(
        find.byKey(const Key('action-confirm')).hitTestable(),
        findsOneWidget,
      );
      expect(find.text(address), findsWidgets);
      expect(tester.takeException(), isNull);
      await press(tester, 'action-confirm');
      expect(launcher.addresses, [address]);
      expect(
        find.byKey(const Key('rescan-button')).hitTestable(),
        findsOneWidget,
      );
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      camera.detect('SMSTO:01012345678:$body');
      await frames(tester);
      expect(client.requests, hasLength(2));
      client.complete(1, json: analysisResponse(qrType: 'text'));
      await frames(tester);
      expect(find.byKey(const Key('compose-sms')), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  for (final size in [
    const Size(280, 360),
    const Size(568, 280),
    const Size(390, 844),
  ]) {
    testWidgets('waiting frame and scrollable guide fit $size at 2x text', (
      tester,
    ) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await mountPage(
        tester,
        client,
        scale: 2,
        safePadding: const EdgeInsets.fromLTRB(12, 24, 12, 20),
      );
      final cameraRect = tester.getRect(find.byKey(const Key('camera-region')));
      final frame = tester.getRect(find.byKey(const Key('scan-frame')));
      final guide = tester.getRect(find.byKey(const Key('scan-guide-panel')));
      final header = tester.getRect(find.byType(AppBar));
      expect(frame.width, greaterThan(0));
      expect(frame.width, closeTo(frame.height, 0.001));
      expect(cameraRect.contains(frame.topLeft), isTrue);
      expect(cameraRect.contains(frame.bottomRight), isTrue);
      expect(header.bottom, lessThanOrEqualTo(frame.top));
      expect(cameraRect.bottom, lessThanOrEqualTo(guide.top));
      expect(find.byKey(const Key('scan-mask')), findsOneWidget);
      expect(find.text('Qshing'), findsOneWidget);
      final scroll = find.descendant(
        of: find.byKey(const Key('scan-guide-scroll')),
        matching: find.byType(Scrollable),
      );
      await tester.scrollUntilVisible(
        find.text('Wi-Fi'),
        80,
        scrollable: scroll,
      );
      expect(find.text('Wi-Fi').hitTestable(), findsOneWidget);
      expect(client.requests, isEmpty);
      expect(camera.starts, 1);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('reduced motion stops the frame pulse and loading animation', (
    tester,
  ) async {
    Color frameColor() {
      final frame = tester.widget<Container>(
        find.byKey(const Key('scan-frame')),
      );
      return ((frame.decoration! as BoxDecoration).border! as Border).top.color;
    }

    await mountPage(tester, client, disableAnimations: true);
    final fixedColor = frameColor();
    await tester.pump(const Duration(milliseconds: 700));
    expect(frameColor(), fixedColor);
    expect(tester.binding.hasScheduledFrame, isFalse);
    // Settings can change without starting another camera or listener.
    await mountPage(tester, client);
    final animatedColor = frameColor();
    await tester.pump(const Duration(milliseconds: 700));
    expect(frameColor(), isNot(animatedColor));
    expect(camera.starts, 1);
    await mountPage(tester, client, disableAnimations: true);
    camera.detect('QR');
    await frames(tester);
    expect(find.byIcon(Icons.hourglass_top_rounded), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsNothing);
    client.complete(0);
    await frames(tester);
    await tester.pumpAndSettle();
    expect(tester.binding.hasScheduledFrame, isFalse);
    expect(find.byKey(const Key('scan-frame')), findsNothing);
    await tester.tap(find.byKey(const Key('rescan-button')));
    await frames(tester);
    expect(camera.starts, 2);
    camera.detect('QR');
    await frames(tester);
    expect(client.requests, hasLength(2));
    client.complete(1);
    await frames(tester);
    expect(tester.takeException(), isNull);
  });

  testWidgets('queued detection error cannot discard an HTTP analysis', (
    tester,
  ) async {
    await mountPage(tester, client);
    camera.detect('QR');
    camera.captures.addError(Exception('old camera event secret'));
    await frames(tester);
    expect(client.requests, hasLength(1));
    expect(find.text('QR 내용 분석 중'), findsOneWidget);
    client.complete(0);
    await frames(tester);
    expect(find.text('낮은 위험'), findsOneWidget);
    expect(find.textContaining('secret'), findsNothing);
  });

  testWidgets(
    'repeated permission failures reuse one native barcode subscription',
    (tester) async {
      const denied = MobileScannerException(
        errorCode: MobileScannerErrorCode.permissionDenied,
      );
      camera.nextStartError = denied;
      await mountPage(tester, client);
      for (var index = 0; index < 2; index++) {
        camera.nextStartError = denied;
        await tester.tap(find.byKey(const Key('rescan-button')));
        await frames(tester);
        expect(find.textContaining('카메라 권한이 필요합니다.'), findsOneWidget);
        expect(camera.peakBarcodeListeners, 1);
      }
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      expect(camera.starts, 4);
      expect(camera.peakBarcodeListeners, 1);
      camera.detect('QR');
      await frames(tester);
      expect(client.requests, hasLength(1));
      expect(camera.barcodeListeners, 0);
      client.complete(0);
      await frames(tester);
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      expect(camera.starts, 5);
      expect(camera.peakBarcodeListeners, 1);
    },
  );

  testWidgets(
    'small scaled error has a scrollable body and visible recovery button',
    (tester) async {
      tester.view.physicalSize = const Size(280, 360);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await mountPage(tester, client, scale: 2);
      camera.detect('QR');
      await frames(tester);
      client.complete(0, status: 500);
      await frames(tester);
      expect(find.byKey(const Key('analysis-error-scroll')), findsOneWidget);
      expect(
        find.byKey(const Key('rescan-button')).hitTestable(),
        findsOneWidget,
      );
      expect(find.byType(MobileScanner), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'waiting to analysis to full result to rescan preserves request contract',
    (tester) async {
      await mountPage(tester, client);
      expect(find.byType(MobileScanner), findsOneWidget);
      expect(find.text('QR 코드를 스캔하세요'), findsOneWidget);
      expect(camera.starts, 1);
      final controller = tester
          .widget<MobileScanner>(find.byType(MobileScanner))
          .controller!;
      expect(controller.autoStart, isFalse);
      camera.detect('확인: example.invalid/Path');
      await frames(tester);
      expect(find.text('QR 내용 분석 중'), findsOneWidget);
      expect(find.byType(MobileScanner), findsNothing);
      expect(find.byKey(const Key('rescan-button')), findsNothing);
      expect(camera.stops, 1);
      expect(client.requests, hasLength(1));
      final request = client.requests.single;
      expect(request.method, 'POST');
      expect(request.url.toString(), 'https://analysis.invalid/analyze-qr');
      expect(
        request.headers['Content-Type'],
        'application/json; charset=utf-8',
      );
      expect(jsonDecode(request.body), {'content': '확인: example.invalid/Path'});
      client.complete(0);
      await frames(tester);
      expect(find.text('Qshing'), findsOneWidget);
      expect(find.text('낮은 위험'), findsOneWidget);
      expect(find.byType(MobileScanner), findsNothing);
      final button = find.byKey(const Key('rescan-button'));
      expect(button.hitTestable(), findsOneWidget);
      expect(
        tester.getSize(find.byType(AnalysisResultView)).height,
        greaterThan(350),
      );
      expect(
        find.descendant(
          of: find.byType(AnalysisResultView),
          matching: find.byType(FilledButton),
        ),
        findsNothing,
      );
      await tester.tap(button);
      await frames(tester);
      expect(find.text('낮은 위험'), findsNothing);
      expect(find.byType(MobileScanner), findsOneWidget);
      expect(
        identical(
          tester.widget<MobileScanner>(find.byType(MobileScanner)).controller,
          controller,
        ),
        isTrue,
      );
      expect(camera.starts, 2);
      expect(camera.maxActiveOperations, 1);
      expect(camera.peakBarcodeListeners, 1);
    },
  );

  testWidgets('API failure uses full error body and allows same QR recovery', (
    tester,
  ) async {
    await mountPage(tester, client);
    camera.detect('same QR');
    await frames(tester);
    client.complete(0, status: 500, json: {'detail': 'Traceback secret'});
    await frames(tester);
    expect(find.text('오류 발생'), findsOneWidget);
    expect(find.textContaining('서버에서 오류'), findsOneWidget);
    expect(find.textContaining('secret'), findsNothing);
    expect(find.byType(MobileScanner), findsNothing);
    await tester.tap(find.byKey(const Key('rescan-button')));
    await frames(tester);
    expect(find.text('오류 발생'), findsNothing);
    camera.detect('same QR');
    await frames(tester);
    expect(client.requests, hasLength(2));
    client.complete(1);
    await frames(tester);
    expect(find.text('낮은 위험'), findsOneWidget);
  });

  testWidgets(
    'duplicate detection and repeated stale button callbacks do not duplicate starts or requests',
    (tester) async {
      await mountPage(tester, client);
      for (var index = 0; index < 5; index++) {
        camera.detect('same QR');
      }
      await frames(tester);
      expect(client.requests, hasLength(1));
      camera.detect('different QR');
      await frames(tester);
      expect(client.requests, hasLength(1));
      client.complete(0);
      await frames(tester);
      final callback = tester
          .widget<FilledButton>(find.byKey(const Key('rescan-button')))
          .onPressed!;
      await tester.tap(find.byKey(const Key('rescan-button')));
      await tester.tap(find.byKey(const Key('rescan-button')));
      callback();
      callback();
      callback();
      await frames(tester);
      expect(camera.starts, 2);
      expect(camera.maxActiveOperations, 1);
      expect(camera.peakBarcodeListeners, 1);
      for (var index = 0; index < 3; index++) {
        camera.detect('same QR');
      }
      await frames(tester);
      expect(client.requests, hasLength(2));
      client.complete(1);
      await frames(tester);
    },
  );

  testWidgets(
    'result and error states stay stopped across background and resume',
    (tester) async {
      for (final status in [200, 500]) {
        await mountPage(tester, client);
        camera.detect('QR $status');
        await frames(tester);
        client.complete(client.responses.length - 1, status: status);
        await frames(tester);
        final starts = camera.starts;
        for (final lifecycle in [
          AppLifecycleState.inactive,
          AppLifecycleState.hidden,
          AppLifecycleState.paused,
          AppLifecycleState.hidden,
          AppLifecycleState.inactive,
          AppLifecycleState.resumed,
        ]) {
          tester.binding.handleAppLifecycleStateChanged(lifecycle);
          await frames(tester);
        }
        expect(camera.starts, starts);
        expect(find.byType(MobileScanner), findsNothing);
        expect(find.text(status == 200 ? '낮은 위험' : '오류 발생'), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
        await frames(tester);
      }
    },
  );

  testWidgets(
    'waiting camera pauses and resumes once without duplicated listeners',
    (tester) async {
      await mountPage(tester, client);
      await background(tester);
      camera.detect('background QR');
      await frames(tester);
      expect(client.requests, isEmpty);
      expect(camera.stops, 1);
      await resume(tester);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await frames(tester);
      expect(camera.starts, 2);
      expect(camera.peakBarcodeListeners, 1);
      camera.detect('foreground QR');
      await frames(tester);
      expect(client.requests, hasLength(1));
      client.complete(0);
      await frames(tester);
    },
  );

  testWidgets(
    'request completing in background preserves result without restarting camera',
    (tester) async {
      await mountPage(tester, client);
      camera.detect('QR');
      await frames(tester);
      await background(tester);
      client.complete(0);
      await frames(tester);
      await resume(tester);
      expect(find.text('낮은 위험'), findsOneWidget);
      expect(camera.starts, 1);
    },
  );

  testWidgets('background while camera start is pending stops the late start', (
    tester,
  ) async {
    final gate = Completer<void>();
    camera.startGate = gate;
    await mountPage(tester, client);
    await background(tester);
    gate.complete();
    await frames(tester);
    expect(camera.starts, 1);
    expect(camera.stops, 1);
    expect(client.requests, isEmpty);
    await resume(tester);
    expect(camera.starts, 2);
    expect(camera.maxActiveOperations, 1);
  });

  testWidgets(
    'dispose before API response causes no setState and does not close caller client',
    (tester) async {
      await mountPage(tester, client);
      camera.detect('QR');
      await frames(tester);
      await tester.pumpWidget(const SizedBox.shrink());
      await frames(tester);
      client.complete(0);
      await frames(tester);
      expect(tester.takeException(), isNull);
      expect(find.byType(AnalysisResultView), findsNothing);
      expect(camera.disposals, 1);
      expect(client.closed, isFalse);
    },
  );

  testWidgets(
    'dispose during pending camera start serializes stop and dispose',
    (tester) async {
      final gate = Completer<void>();
      camera.startGate = gate;
      await mountPage(tester, client);
      await tester.pumpWidget(const SizedBox.shrink());
      await frames(tester);
      expect(camera.disposals, 0);
      gate.complete();
      await frames(tester);
      expect(camera.stops, 1);
      expect(camera.disposals, 1);
      expect(camera.maxActiveOperations, 1);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    '15 second timeout can rescan and old response cannot overwrite new result',
    (tester) async {
      await mountPage(tester, client);
      camera.detect('old QR');
      await frames(tester);
      await tester.pump(const Duration(seconds: 14));
      expect(find.text('QR 내용 분석 중'), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      await frames(tester);
      expect(find.textContaining('서버 응답 시간이 초과'), findsOneWidget);
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      camera.detect('new QR');
      await frames(tester);
      client.complete(0, json: analysisResponse()..['risk_score'] = 99);
      await frames(tester);
      expect(find.text('QR 내용 분석 중'), findsOneWidget);
      expect(find.text('위험 점수 99'), findsNothing);
      client.complete(1, json: analysisResponse()..['risk_score'] = 17);
      await frames(tester);
      expect(find.text('위험 점수 17'), findsOneWidget);
      expect(camera.starts, 2);
    },
  );

  testWidgets(
    'camera permission denial is recoverable and never displays native exception text',
    (tester) async {
      camera.nextStartError = const MobileScannerException(
        errorCode: MobileScannerErrorCode.permissionDenied,
      );
      await mountPage(tester, client);
      expect(find.textContaining('기기 설정에서 카메라 권한을 허용'), findsOneWidget);
      expect(find.byType(MobileScanner), findsNothing);
      expect(client.requests, isEmpty);
      await tester.tap(find.byKey(const Key('rescan-button')));
      await frames(tester);
      expect(find.byType(MobileScanner), findsOneWidget);
      expect(camera.starts, 2);
      camera.detect('QR');
      await frames(tester);
      expect(client.requests, hasLength(1));
      expect(camera.peakBarcodeListeners, 1);
      client.complete(0);
      await frames(tester);
    },
  );

  testWidgets('camera start error displays generic full page recovery', (
    tester,
  ) async {
    camera.nextStartError = const MobileScannerException(
      errorCode: MobileScannerErrorCode.genericError,
      errorDetails: MobileScannerErrorDetails(
        message: 'Traceback secret native error',
      ),
    );
    await mountPage(tester, client);
    expect(find.textContaining('카메라를 사용할 수 없습니다.'), findsOneWidget);
    expect(find.textContaining('secret'), findsNothing);
    expect(
      find.byKey(const Key('rescan-button')).hitTestable(),
      findsOneWidget,
    );
  });

  testWidgets(
    'missing API configuration and invalid response are generic recoverable errors',
    (tester) async {
      await mountPage(tester, client, endpoint: '');
      camera.detect('QR');
      await frames(tester);
      expect(find.textContaining('분석 서비스를 사용할 수 없습니다.'), findsOneWidget);
      expect(client.requests, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
      await frames(tester);
      await mountPage(tester, client);
      camera.detect('QR');
      await frames(tester);
      client.complete(0, json: {'internal_error': 'secret'});
      await frames(tester);
      expect(find.textContaining('분석 결과를 처리하는 중 오류'), findsOneWidget);
      expect(find.textContaining('secret'), findsNothing);
    },
  );

  testWidgets(
    'small scaled screen uses whole result body and an always reachable single bottom action',
    (tester) async {
      tester.view.physicalSize = const Size(280, 568);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await mountPage(tester, client, scale: 2);
      expect(tester.takeException(), isNull);
      camera.detect('QR');
      await frames(tester);
      final longUrl =
          'https://example.invalid/${'LongPath' * 40}?Token=${'AbC' * 100}';
      final json =
          withEmbeddedUrls([
            embeddedResponse(url: longUrl)
              ..addAll(requestedReport())
              ..addAll({
                'assumed_https': true,
                'original_candidates': ['example.invalid/Path'],
                'reasons': ['긴 사유 ${'위험 신호 ' * 50}'],
              }),
            embeddedResponse(url: 'https://stored.invalid')
              ..addAll(historicalReport()),
          ])..addAll({
            'embedded_url_analysis_complete': false,
            'embedded_url_count': 5,
            'analysis_flags': {'embedded_url_skipped_count': 2},
            'embedded_url_failures': [
              {
                'analysis_url': 'https://failed.invalid',
                'error_code': 'EMBEDDED_URL_ANALYSIS_FAILED',
              },
            ],
          });
      client.complete(0, json: json);
      await frames(tester);
      expect(tester.takeException(), isNull);
      expect(find.text('일부 링크의 분석을 완료하지 못했습니다.'), findsOneWidget);
      expect(
        find.textContaining('실제 HTTPS 지원 여부는 확인하지 않았습니다.'),
        findsOneWidget,
      );
      expect(find.textContaining('과거 악성 탐지 3건'), findsOneWidget);
      expect(find.text(longUrl), findsOneWidget);
      expect(find.byType(FilledButton), findsOneWidget);
      final button = find.byKey(const Key('rescan-button'));
      expect(button.hitTestable(), findsOneWidget);
      final originalButtonRect = tester.getRect(button);
      await tester.ensureVisible(
        find.byKey(const ValueKey('embedded-failure-0')),
      );
      await frames(tester);
      expect(tester.getRect(button), originalButtonRect);
      expect(button.hitTestable(), findsOneWidget);
      expect(find.text('https://failed.invalid'), findsOneWidget);
      await tester.tap(button);
      await frames(tester);
      expect(find.byType(AnalysisResultView), findsNothing);
      expect(find.byType(MobileScanner), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
}
