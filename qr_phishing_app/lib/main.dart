import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';

import 'analysis_result.dart';
import 'result_actions.dart';

part 'analysis_result_view.dart';

void main() {
  runApp(const QrPhishingApp());
}

// ── 색상 팔레트 ──────────────────────────────────────────
class AppColors {
  static const bg = Color(0xFFF4F6FA);
  static const surface = Color(0xFFFFFFFF);
  static const surfaceSub = Color(0xFFEEF1F7);
  static const border = Color(0x14000000);
  static const textPrim = Color(0xFF1A1D26);
  static const textSec = Color(0xFF3A3F52);
  static const textHint = Color(0xFF7A8099);

  static const safe = Color(0xFF0E9E5A);
  static const safeBg = Color(0x140E9E5A);
  static const warning = Color(0xFFC47A00);
  static const warningBg = Color(0x14C47A00);
  static const danger = Color(0xFFD63030);
  static const dangerBg = Color(0x12D63030);
  static const accent = Color(0xFF2563EB);
  static const accentBg = Color(0x102563EB);
}

// ── QR 유형 한글화 ───────────────────────────────────────
String qrTypeLabel(dynamic raw) {
  const map = {
    'url': 'URL',
    'text': '일반 텍스트',
    'text_with_url': 'URL 포함 텍스트',
    'phone': '전화번호',
    'phone_text': '전화번호 포함 텍스트',
    'sms': 'SMS',
    'email': '이메일',
    'email_text': '이메일 포함 텍스트',
    'wifi': 'Wi-Fi',
    'dangerous_scheme': '위험 스킴',
  };
  return map[raw?.toString()] ?? '기타';
}

// ────────────────────────────────────────────────────────
class QrPhishingApp extends StatelessWidget {
  const QrPhishingApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Qshing',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: AppColors.accent,
        scaffoldBackgroundColor: AppColors.bg,
        appBarTheme: const AppBarTheme(
          backgroundColor: AppColors.surface,
          foregroundColor: AppColors.textPrim,
          elevation: 0,
          centerTitle: true,
          titleTextStyle: TextStyle(
            color: AppColors.textPrim,
            fontSize: 17,
            fontWeight: FontWeight.w600,
            letterSpacing: -0.3,
          ),
        ),
      ),
      home: const ScanPage(),
    );
  }
}

// ────────────────────────────────────────────────────────
class ScanPage extends StatefulWidget {
  const ScanPage({
    super.key,
    this.client,
    this.launcher = const SystemExternalAppLauncher(),
    this.apiUrl = const String.fromEnvironment('API_URL', defaultValue: ''),
  });

  // An injected client stays owned by its caller. Production creates its own.
  final http.Client? client;
  final ExternalAppLauncher launcher;
  final String apiUrl;

  @override
  State<ScanPage> createState() => _ScanPageState();
}

enum _ScanPhase { scanning, analyzing, result, error }

class _ScanPageState extends State<ScanPage>
    with TickerProviderStateMixin, WidgetsBindingObserver {
  // ScanPage owns start/stop/dispose. The preview must never auto-start when
  // mounted again, or independently react to app lifecycle changes.
  final MobileScannerController _scannerController = MobileScannerController(
    autoStart: false,
  );
  late final http.Client _client;
  late final bool _ownsClient;
  StreamSubscription<BarcodeCapture>? _barcodeSubscription;
  Future<void> _cameraOperations = Future<void>.value();
  _ScanPhase _phase = _ScanPhase.scanning;
  bool _foreground = true;
  bool _cameraReady = false;
  bool _reuseStartListeners = false;
  bool _disposed = false;
  bool _reduceMotion = false;
  int _requestGeneration = 0;

  AnalysisResult? _result;
  String? _errorMessage;
  // Only an explicit SMS/SMSTO payload is retained for this scan session.
  // Never use server previews/masked fields, and never persist or log this.
  String? _sessionSmsQr;
  bool _actionBusy = false;
  bool _launchInFlight = false;
  DialogRoute<bool>? _actionDialog;

  late final AnimationController _pulseController;
  late final Animation<double> _pulseAnim;

  static const Duration _apiTimeout = Duration(seconds: 15);

  @override
  void initState() {
    super.initState();
    _ownsClient = widget.client == null;
    _client = widget.client ?? http.Client();
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    _foreground = lifecycle == null || lifecycle == AppLifecycleState.resumed;
    // Initialize while the element is active, even if camera startup fails or
    // is still pending when the page is disposed.
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );
    _pulseAnim = Tween<double>(begin: 0.6, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
    WidgetsBinding.instance.addObserver(this);
    // Exactly one application listener for the lifetime of the page. The
    // preview only displays the controller; it does not subscribe onDetect.
    _barcodeSubscription = _scannerController.barcodes.listen(
      _onDetect,
      onError: (Object error) {
        // A queued detection error belongs to the scanning session, not an
        // HTTP analysis already in progress or a displayed result.
        if (_canScan) _cameraFailed(error);
      },
    );
    _scheduleCameraSync();
  }

  bool get _canScan =>
      !_disposed && mounted && _foreground && _phase == _ScanPhase.scanning;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _reduceMotion = MediaQuery.disableAnimationsOf(context);
    _syncPulse();
  }

  void _syncPulse() {
    if (_canScan && !_reduceMotion) {
      if (!_pulseController.isAnimating) {
        _pulseController.repeat(reverse: true);
      }
    } else {
      _pulseController.stop();
      if (_reduceMotion) _pulseController.value = 1;
    }
  }

  void _scheduleCameraSync() {
    // Attach the initial preview before start; rebuild rescan state first too.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_disposed && mounted) unawaited(_syncCamera());
    });
  }

  Future<void> _syncCamera() {
    // Serialize native operations. Lifecycle changes while start is pending
    // are rechecked after it completes, so a late start cannot revive a camera
    // behind a result, in the background, or after disposal.
    _cameraOperations = _cameraOperations.then((_) async {
      if (_disposed) return;
      try {
        if (_canScan) {
          if (!_scannerController.value.isRunning) {
            await _startCamera();
          }
          if (_canScan) {
            final error = _scannerController.value.error;
            if (error != null) {
              _cameraFailed(error);
            } else if (_scannerController.value.isRunning) {
              setState(() {
                _cameraReady = true;
              });
            } else {
              _cameraFailed(null);
            }
          }
        }
        if (!_canScan) {
          _cameraReady = false;
          await _scannerController.stop();
        }
      } catch (error) {
        _cameraReady = false;
        _cameraFailed(error);
      }
    });
    return _cameraOperations;
  }

  Future<void> _startCamera() async {
    final controller = _scannerController;
    if (!_reuseStartListeners) {
      try {
        await controller.start();
      } finally {
        _reuseStartListeners =
            controller.value.error != null || controller.value.isStarting;
      }
      return;
    }
    // mobile_scanner 7.2 retains its platform subscriptions after failed start;
    // another controller.start() overwrites them without cancellation. Retry
    // only the public platform start, reusing those subscriptions. On success
    // normal controller.stop() cancels them, and later starts use the SDK again.
    // Keep this compatibility path covered when upgrading mobile_scanner.
    final view = await MobileScannerPlatform.instance.start(
      StartOptions(
        cameraDirection: controller.facing,
        cameraLensType: controller.lensType,
        cameraResolution: controller.cameraResolution,
        detectionSpeed: controller.detectionSpeed,
        detectionTimeoutMs: controller.detectionTimeoutMs,
        formats: controller.formats,
        returnImage: controller.returnImage,
        torchEnabled: controller.torchEnabled,
        invertImage: controller.invertImage,
        autoZoom: controller.autoZoom,
        initialZoom: controller.initialZoom,
      ),
    );
    controller.value = controller.value.copyWith(
      availableCameras: view.numberOfCameras,
      cameraDirection: view.cameraDirection,
      cameraLensType: controller.lensType,
      isInitialized: true,
      isStarting: false,
      isRunning: true,
      size: view.size,
      deviceOrientation: view.initialDeviceOrientation,
      torchState: view.currentTorchMode,
    );
    _reuseStartListeners = false;
  }

  void _cameraFailed(Object? error) {
    if (_disposed ||
        !mounted ||
        (_phase != _ScanPhase.scanning && _phase != _ScanPhase.analyzing)) {
      return;
    }
    _requestGeneration++;
    _pulseController.stop();
    setState(() {
      _cameraReady = false;
      _phase = _ScanPhase.error;
      _sessionSmsQr = null;
      _errorMessage =
          error is MobileScannerException &&
              error.errorCode == MobileScannerErrorCode.permissionDenied
          ? '카메라 권한이 필요합니다. 기기 설정에서 카메라 권한을 허용한 뒤 다시 스캔해주세요.'
          : '카메라를 사용할 수 없습니다. 다른 앱의 카메라 사용을 종료한 뒤 다시 스캔해주세요.';
    });
    // Called inside the operation queue too: do not await the next operation.
    unawaited(_syncCamera());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_disposed || !mounted) return;
    setState(() {
      _foreground = state == AppLifecycleState.resumed;
      if (!_foreground) _cameraReady = false;
    });
    _syncPulse();
    unawaited(_syncCamera());
  }

  void _onDetect(BarcodeCapture capture) {
    if (!_canScan || !_cameraReady) return;
    for (final barcode in capture.barcodes) {
      final content = barcode.rawValue;
      if (content == null || content.isEmpty) continue;
      // Lock synchronously, before stop or the HTTP request can yield.
      final generation = ++_requestGeneration;
      _pulseController.stop();
      setState(() {
        _phase = _ScanPhase.analyzing;
        _cameraReady = false;
        _result = null;
        _errorMessage = null;
        final lower = content.trim().toLowerCase();
        _sessionSmsQr = lower.startsWith('sms:') || lower.startsWith('smsto:')
            ? content
            : null;
      });
      unawaited(_analyzeQRContent(content, generation));
      break;
    }
  }

  bool _isCurrentRequest(int generation) =>
      !_disposed &&
      mounted &&
      generation == _requestGeneration &&
      _phase == _ScanPhase.analyzing;

  String _httpErrorMessage(int statusCode) {
    if (statusCode == 400 || statusCode == 422) {
      return 'QR 내용을 분석할 수 없습니다.';
    }
    if (statusCode >= 500) {
      return '서버에서 오류가 발생했습니다.\n잠시 후 다시 시도해주세요.';
    }
    return 'QR 분석 중 오류가 발생했습니다.';
  }

  AnalysisResult _parseAnalysisResponse(http.Response response) {
    return AnalysisResult.fromBodyBytes(response.bodyBytes);
  }

  Future<void> _analyzeQRContent(String qrContent, int generation) async {
    await _syncCamera();
    if (!_isCurrentRequest(generation)) return;
    try {
      if (widget.apiUrl.trim().isEmpty) {
        _analysisFailed(generation, '분석 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해주세요.');
        return;
      }
      final response = await _client
          .post(
            Uri.parse(widget.apiUrl),
            headers: {'Content-Type': 'application/json; charset=utf-8'},
            body: jsonEncode({'content': qrContent}),
          )
          .timeout(_apiTimeout);

      if (!_isCurrentRequest(generation)) return;

      if (response.statusCode != 200) {
        _analysisFailed(generation, _httpErrorMessage(response.statusCode));
        return;
      }

      final data = _parseAnalysisResponse(response);

      if (!_isCurrentRequest(generation)) return;
      setState(() {
        _result = data;
        _phase = _ScanPhase.result;
      });
    } on TimeoutException {
      _analysisFailed(generation, '서버 응답 시간이 초과되었습니다.\n잠시 후 다시 시도해주세요.');
    } on FormatException {
      _analysisFailed(generation, '분석 결과를 처리하는 중 오류가 발생했습니다.');
    } on TypeError {
      _analysisFailed(generation, '분석 결과를 처리하는 중 오류가 발생했습니다.');
    } catch (_) {
      _analysisFailed(generation, 'QR 분석 중 오류가 발생했습니다.');
    }
  }

  void _analysisFailed(int generation, String message) {
    if (!_isCurrentRequest(generation)) return;
    setState(() {
      _errorMessage = message;
      _phase = _ScanPhase.error;
      _sessionSmsQr = null;
    });
  }

  void _resetScan() {
    // The first tap changes phase immediately; stale button callbacks and
    // rapid repeated taps cannot enqueue another reset/start.
    if (_disposed ||
        !mounted ||
        (_phase != _ScanPhase.result && _phase != _ScanPhase.error)) {
      return;
    }

    _requestGeneration++;
    _dismissActionDialog();
    setState(() {
      _result = null;
      _errorMessage = null;
      _phase = _ScanPhase.scanning;
      _cameraReady = false;
      _sessionSmsQr = null;
      _actionBusy = false;
    });
    _syncPulse();
    _scheduleCameraSync();
  }

  @override
  void dispose() {
    _disposed = true;
    _requestGeneration++;
    _sessionSmsQr = null;
    // Navigation can be locked while a page is being removed. Invalidate now
    // and remove any surviving modal on the next frame, without using context.
    final dialog = _actionDialog;
    _actionDialog = null;
    if (dialog != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        final navigator = dialog.navigator;
        if (dialog.isActive && navigator != null && navigator.mounted) {
          navigator.removeRoute(dialog);
        }
      });
    }
    WidgetsBinding.instance.removeObserver(this);
    unawaited(_barcodeSubscription?.cancel());
    if (_ownsClient) _client.close();
    // Finish a pending native start before stopping/disposal. Never overlap
    // controller.dispose with an in-flight platform start.
    unawaited(
      _cameraOperations.then((_) async {
        try {
          await _scannerController.stop();
        } catch (_) {
          /* Best effort. */
        }
        try {
          await _scannerController.dispose();
        } catch (_) {
          /* Best effort. */
        }
      }),
    );
    _pulseController.dispose();
    super.dispose();
  }

  static const _ink = Color(0xFF0F172A);

  @override
  Widget build(BuildContext context) {
    final scanning = _phase == _ScanPhase.scanning;
    final darkHeader = scanning || _phase == _ScanPhase.analyzing;
    return Scaffold(
      backgroundColor: AppColors.bg,
      appBar: AppBar(
        toolbarHeight: MediaQuery.textScalerOf(context).scale(20) + 32,
        backgroundColor: darkHeader ? _ink : AppColors.surface,
        foregroundColor: darkHeader ? Colors.white : AppColors.textPrim,
        centerTitle: false,
        title: Row(
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                color: darkHeader
                    ? Colors.white.withValues(alpha: 0.14)
                    : AppColors.accentBg,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(
                Icons.shield_outlined,
                size: 20,
                color: darkHeader ? Colors.white : AppColors.accent,
              ),
            ),
            const SizedBox(width: 10),
            Flexible(
              child: Text(
                'Qshing',
                style: TextStyle(
                  color: darkHeader ? Colors.white : AppColors.textPrim,
                  fontSize: 20,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -0.4,
                ),
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar:
          _phase == _ScanPhase.result || _phase == _ScanPhase.error
          ? Container(
              decoration: const BoxDecoration(
                color: AppColors.surface,
                border: Border(top: BorderSide(color: AppColors.border)),
              ),
              child: SafeArea(
                top: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
                  child: ScanAgainButton(onPressed: _resetScan),
                ),
              ),
            )
          : null,
      // Keep the same preview/controller attached through every phase. Its
      // native start/stop and lifecycle are still owned by the existing queue.
      body: Stack(
        fit: StackFit.expand,
        children: [
          Offstage(
            offstage: !scanning,
            child: TickerMode(
              enabled: scanning && _foreground && !_reduceMotion,
              child: SafeArea(
                top: false,
                bottom: false,
                child: LayoutBuilder(
                  builder: (context, constraints) => Column(
                    children: [
                      Expanded(child: _buildCameraView()),
                      // Natural panel height on large screens; scroll within a
                      // cap on small screens, leaving real space for the frame.
                      ConstrainedBox(
                        constraints: BoxConstraints(
                          maxHeight: constraints.maxHeight * 0.52,
                        ),
                        child: _buildGuideView(),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
          if (_phase == _ScanPhase.analyzing)
            ColoredBox(color: _ink, child: _buildProgressView()),
          if (_phase == _ScanPhase.result || _phase == _ScanPhase.error)
            SafeArea(
              top: false,
              child: _phase == _ScanPhase.error
                  ? _buildErrorView()
                  : _buildResultView(),
            ),
        ],
      ),
    );
  }

  Widget _buildCameraView() => LayoutBuilder(
    builder: (context, constraints) {
      final side = math.max(
        0.0,
        math.min(
          300.0,
          math.min(constraints.maxWidth - 48, constraints.maxHeight - 40),
        ),
      );
      final hole = Rect.fromCenter(
        center: Offset(constraints.maxWidth / 2, constraints.maxHeight / 2),
        width: side,
        height: side,
      );
      return Stack(
        key: const Key('camera-region'),
        fit: StackFit.expand,
        children: [
          MobileScanner(
            key: const Key('scan-camera'),
            controller: _scannerController,
            useAppLifecycleState: false,
            errorBuilder: (context, error) => const SizedBox.shrink(),
          ),
          if (_cameraReady && side > 0) ...[
            Positioned.fill(
              child: IgnorePointer(
                child: CustomPaint(
                  key: const Key('scan-mask'),
                  painter: _ScanMaskPainter(hole),
                ),
              ),
            ),
            Positioned.fromRect(
              rect: hole,
              child: IgnorePointer(
                child: AnimatedBuilder(
                  animation: _pulseAnim,
                  builder: (context, child) => Container(
                    key: const Key('scan-frame'),
                    decoration: BoxDecoration(
                      border: Border.all(
                        color: Colors.white.withValues(
                          alpha: 0.45 + 0.45 * _pulseAnim.value,
                        ),
                        width: 2.5,
                      ),
                      borderRadius: BorderRadius.circular(28),
                    ),
                  ),
                ),
              ),
            ),
          ],
          if (!_cameraReady)
            ColoredBox(
              color: _ink,
              child: Center(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (_reduceMotion)
                        const Icon(
                          Icons.camera_alt_outlined,
                          color: Colors.white,
                          size: 40,
                        )
                      else
                        const CircularProgressIndicator(color: Colors.white),
                      const SizedBox(height: 16),
                      const Text(
                        '카메라 준비 중',
                        textAlign: TextAlign.center,
                        style: TextStyle(color: Colors.white, fontSize: 16),
                      ),
                    ],
                  ),
                ),
              ),
            ),
        ],
      );
    },
  );

  Widget _buildGuideView() => Container(
    key: const Key('scan-guide-panel'),
    width: double.infinity,
    decoration: const BoxDecoration(
      color: AppColors.surface,
      borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
    ),
    child: SafeArea(
      top: false,
      child: SingleChildScrollView(
        key: const Key('scan-guide-scroll'),
        primary: false,
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: AppColors.accentBg,
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: const Icon(
                    Icons.verified_user_rounded,
                    color: AppColors.accent,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 14),
                const Expanded(
                  child: Text(
                    'QR 코드를 스캔하세요',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.w800,
                      color: AppColors.textPrim,
                      letterSpacing: -0.4,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              'QR 코드를 네모 안에 맞춰주세요',
              style: TextStyle(fontSize: 14, color: AppColors.textSec),
            ),
            const SizedBox(height: 8),
            const Text(
              'QR을 자동으로 열지 않고, 먼저 위험도를 분석합니다.',
              style: TextStyle(
                fontSize: 14,
                color: AppColors.textSec,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 16),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _infoChip(Icons.link_rounded, 'URL'),
                _infoChip(Icons.phone_outlined, '전화번호'),
                _infoChip(Icons.sms_outlined, '문자'),
                _infoChip(Icons.mail_outline_rounded, '이메일'),
                _infoChip(Icons.wifi_rounded, 'Wi-Fi'),
              ],
            ),
          ],
        ),
      ),
    ),
  );

  Widget _infoChip(IconData icon, String label) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
    decoration: BoxDecoration(
      color: AppColors.surfaceSub,
      borderRadius: BorderRadius.circular(20),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: AppColors.accent),
        const SizedBox(width: 6),
        Text(
          label,
          style: const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: AppColors.textSec,
          ),
        ),
      ],
    ),
  );

  Widget _buildErrorView() {
    final message = _errorMessage ?? '';
    final icon = message.contains('카메라 권한')
        ? Icons.no_photography_outlined
        : message.contains('카메라')
        ? Icons.camera_alt_outlined
        : message.contains('시간')
        ? Icons.timer_off_outlined
        : Icons.cloud_off_rounded;
    return SingleChildScrollView(
      key: const Key('analysis-error-scroll'),
      padding: const EdgeInsets.all(24),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: AppColors.border),
        ),
        child: Column(
          children: [
            Container(
              width: 88,
              height: 88,
              decoration: const BoxDecoration(
                color: AppColors.dangerBg,
                shape: BoxShape.circle,
              ),
              child: Icon(icon, size: 40, color: AppColors.danger),
            ),
            const SizedBox(height: 20),
            const Text(
              '오류 발생',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w800,
                color: AppColors.textPrim,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 14,
                color: AppColors.textSec,
                height: 1.6,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultView() {
    final generation = _requestGeneration;
    final result = _result!;
    final draft = result.qrType == 'sms' && _sessionSmsQr != null
        ? parseSmsDraft(_sessionSmsQr!)
        : null;
    return AnalysisResultView(
      result: result,
      actionsBusy: _actionBusy || _launchInFlight,
      smsAvailable: draft != null,
      onOpenLink: (target) => _openLink(target, generation),
      onComposeSms: () {
        if (draft != null) _composeSms(draft, generation);
      },
    );
  }

  bool _isActionSession(int generation) =>
      !_disposed &&
      mounted &&
      generation == _requestGeneration &&
      _phase == _ScanPhase.result;

  void _dismissActionDialog() {
    final dialog = _actionDialog;
    _actionDialog = null;
    if (dialog != null && dialog.isActive) {
      dialog.navigator?.removeRoute(dialog);
    }
  }

  void _actionMessage(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  List<Widget> _actionWarnings({String? linkStatus}) => [
    if (_result!.status == 'warning' || linkStatus == 'warning')
      const Text('주의 판정입니다. 내용을 충분히 확인한 뒤 진행하세요.'),
    if (_result!.isIncomplete) ...[
      const Text('일부 링크의 분석을 완료하지 못했습니다.'),
      if ((_result!.skippedEmbeddedUrlCount ?? 0) > 0)
        Text('분석 개수 제한으로 ${_result!.skippedEmbeddedUrlCount}개 링크를 검사하지 못했습니다.'),
    ],
    const Text('분석 결과는 실제 안전성을 보장하지 않습니다.'),
  ];

  void _openLink(LinkActionTarget target, int generation) {
    if (!_isActionSession(generation)) return;
    if (_result!.status == 'danger' || target.status == 'danger') {
      _actionMessage('위험 판정으로 링크 열기를 제한했습니다.');
      return;
    }
    if (!isLaunchableWebAddress(target.address)) return;
    unawaited(
      _confirmAndLaunch(
        generation: generation,
        title: '링크 열기 확인',
        confirmLabel: '링크 열기',
        address: target.address,
        content: [
          const Text('실행할 주소'),
          SelectableText(target.address, key: const Key('action-link-address')),
          if (target.assumedHttps) ...[
            for (final original in target.originalCandidates)
              SelectableText('원본 후보: $original'),
            const Text('분석을 위해 HTTPS를 가정했습니다. 실제 HTTPS 지원 여부는 확인하지 않았습니다.'),
          ],
          ..._actionWarnings(linkStatus: target.status),
          Text(reputationNoticeText(target.reputation)),
        ],
      ),
    );
  }

  void _composeSms(SmsDraft draft, int generation) {
    if (!_isActionSession(generation)) return;
    if (_result!.status == 'danger') {
      _actionMessage('위험 판정으로 문자 작성을 제한했습니다.');
      return;
    }
    unawaited(
      _confirmAndLaunch(
        generation: generation,
        title: '문자 작성 확인',
        confirmLabel: '문자 앱 열기',
        address: draft.address,
        content: [
          const Text('수신 번호'),
          SelectableText(
            draft.recipient,
            key: const Key('action-sms-recipient'),
          ),
          const Text('본문'),
          SelectableText(
            draft.body.isEmpty ? '(본문 없음)' : draft.body,
            key: const Key('action-sms-body'),
          ),
          const Text('문자 앱의 작성 화면을 엽니다. 전송은 문자 앱에서 직접 진행하세요.'),
          ..._actionWarnings(),
        ],
      ),
    );
  }

  Future<void> _confirmAndLaunch({
    required int generation,
    required String title,
    required String confirmLabel,
    required String address,
    required List<Widget> content,
  }) async {
    if (!_isActionSession(generation) ||
        !_foreground ||
        _actionBusy ||
        _launchInFlight) {
      return;
    }
    setState(() {
      _actionBusy = true;
    });
    var launched = false;
    var answered = false;
    late final DialogRoute<bool> dialog;
    dialog = DialogRoute<bool>(
      context: context,
      builder: (dialogContext) {
        void finish(bool confirmed) {
          if (answered || !dialog.isCurrent || !_isActionSession(generation)) {
            return;
          }
          answered = true;
          Navigator.of(dialogContext).pop(confirmed);
        }

        return AlertDialog(
          key: const Key('result-action-dialog'),
          title: Text(title),
          scrollable: true,
          content: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final item in content)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: item,
                ),
            ],
          ),
          actions: [
            TextButton(
              key: const Key('action-cancel'),
              onPressed: () => finish(false),
              child: const Text('취소'),
            ),
            TextButton(
              key: const Key('action-confirm'),
              onPressed: () => finish(true),
              child: Text(confirmLabel),
            ),
          ],
        );
      },
    );
    _actionDialog = dialog;
    try {
      final confirmed = await Navigator.of(context).push(dialog);
      if (_actionDialog == dialog) _actionDialog = null;
      if (!_isActionSession(generation) || !_foreground) return;
      if (confirmed != true) {
        _actionMessage('실행을 취소했습니다.');
        return;
      }
      // No asynchronous gap between the final session check and OS dispatch.
      launched = true;
      _launchInFlight = true;
      final opened = await widget.launcher.open(address);
      if (!opened && _isActionSession(generation)) {
        _actionMessage('외부 앱을 열지 못했습니다. 잠시 후 다시 시도해주세요.');
      }
    } catch (_) {
      if (_isActionSession(generation)) {
        _actionMessage('외부 앱을 열지 못했습니다. 잠시 후 다시 시도해주세요.');
      }
    } finally {
      if (!_disposed && mounted) {
        setState(() {
          if (_isActionSession(generation)) _actionBusy = false;
          if (launched) _launchInFlight = false;
        });
      }
    }
  }

  Widget _buildProgressView() => Center(
    child: SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_reduceMotion)
            const Icon(
              Icons.hourglass_top_rounded,
              color: Colors.white,
              size: 48,
            )
          else
            const SizedBox(
              width: 64,
              height: 64,
              child: CircularProgressIndicator(
                color: Colors.white,
                strokeWidth: 3,
                strokeCap: StrokeCap.round,
              ),
            ),
          const SizedBox(height: 24),
          const Text(
            'QR 내용 분석 중',
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 10),
          Text(
            'QR 내용과 포함 링크를 확인하고 있습니다.',
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.white.withValues(alpha: 0.7),
              fontSize: 14,
              height: 1.5,
            ),
          ),
        ],
      ),
    ),
  );
}

// One accessible action outside the scrolling body, for results and errors.
class ScanAgainButton extends StatelessWidget {
  const ScanAgainButton({super.key, required this.onPressed});
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: FilledButton.icon(
        key: const Key('rescan-button'),
        onPressed: onPressed,
        icon: const Icon(Icons.qr_code_scanner_rounded, size: 18),
        label: const Padding(
          padding: EdgeInsets.symmetric(vertical: 14),
          child: Text(
            '다시 스캔하기',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
          ),
        ),
        style: FilledButton.styleFrom(
          backgroundColor: AppColors.accent,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
        ),
      ),
    );
  }
}

class _ScanMaskPainter extends CustomPainter {
  const _ScanMaskPainter(this.hole);
  final Rect hole;

  @override
  void paint(Canvas canvas, Size size) {
    final mask = Path()
      ..fillType = PathFillType.evenOdd
      ..addRect(Offset.zero & size)
      ..addRRect(RRect.fromRectAndRadius(hole, const Radius.circular(28)));
    canvas.drawPath(
      mask,
      Paint()..color = Colors.black.withValues(alpha: 0.55),
    );
  }

  @override
  bool shouldRepaint(_ScanMaskPainter oldDelegate) => oldDelegate.hole != hole;
}
