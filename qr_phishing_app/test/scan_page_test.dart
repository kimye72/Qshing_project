import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_phishing_app/main.dart';

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
  String endpoint = 'https://analysis.invalid/analyze-qr',
}) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: AppColors.accent),
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(
          context,
        ).copyWith(textScaler: TextScaler.linear(scale)),
        child: child!,
      ),
      home: ScanPage(client: client, apiUrl: endpoint),
    ),
  );
  await frames(tester);
}

void main() {
  late FakeCamera camera;
  late FakeAnalysisClient client;
  late MobileScannerPlatform originalPlatform;

  setUp(() {
    TestWidgetsFlutterBinding.ensureInitialized()
        .handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    originalPlatform = MobileScannerPlatform.instance;
    camera = FakeCamera();
    client = FakeAnalysisClient();
    MobileScannerPlatform.instance = camera;
  });

  tearDown(() async {
    await camera.close();
    MobileScannerPlatform.instance = originalPlatform;
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
      expect(find.text('QR 피싱 방지 시스템'), findsOneWidget);
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
