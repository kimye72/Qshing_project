import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';

import 'analysis_result.dart';

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
      title: 'QR 피싱 방지 시스템',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: AppColors.accent,
        scaffoldBackgroundColor: AppColors.bg,
        fontFamily: 'Pretendard',
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
    this.apiUrl = const String.fromEnvironment('API_URL', defaultValue: ''),
  });

  // An injected client stays owned by its caller. Production creates its own.
  final http.Client? client;
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
  int _requestGeneration = 0;

  AnalysisResult? _result;
  String? _errorMessage;

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
    if (_foreground) _pulseController.repeat(reverse: true);
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
    if (!_foreground) {
      _pulseController.stop();
    } else if (_phase == _ScanPhase.scanning) {
      _pulseController.repeat(reverse: true);
    }
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
    setState(() {
      _result = null;
      _errorMessage = null;
      _phase = _ScanPhase.scanning;
      _cameraReady = false;
    });
    if (_foreground) _pulseController.repeat(reverse: true);
    _scheduleCameraSync();
  }

  @override
  void dispose() {
    _disposed = true;
    _requestGeneration++;
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

  // ── 빌드 ─────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        toolbarHeight: MediaQuery.textScalerOf(context).scale(16) * 2 + 24,
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 28,
              height: 28,
              decoration: BoxDecoration(
                color: AppColors.dangerBg,
                border: Border.all(color: AppColors.danger.withOpacity(0.4)),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Icon(
                Icons.qr_code_scanner_rounded,
                size: 16,
                color: AppColors.danger,
              ),
            ),
            const SizedBox(width: 8),
            const Flexible(
              child: Text(
                'QR 피싱 방지 시스템',
                maxLines: 2,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                  letterSpacing: -0.3,
                ),
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar:
          _phase == _ScanPhase.result || _phase == _ScanPhase.error
          ? ColoredBox(
              color: AppColors.surface,
              child: SafeArea(
                top: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
                  child: ScanAgainButton(onPressed: _resetScan),
                ),
              ),
            )
          : null,
      // Keep the preview attached once. Offstage takes no visible space; the
      // native camera is explicitly stopped before HTTP analysis. This also
      // avoids the plugin's debug startup/hot-restart stop on every rescan.
      body: Stack(
        fit: StackFit.expand,
        children: [
          Offstage(
            offstage: _phase != _ScanPhase.scanning,
            child: TickerMode(
              enabled: _phase == _ScanPhase.scanning && _foreground,
              child: Column(
                children: [
                  // ── 카메라 스캔 영역 ──
                  Expanded(
                    flex: 5,
                    child: Stack(
                      children: [
                        MobileScanner(
                          key: const Key('scan-camera'),
                          controller: _scannerController,
                          useAppLifecycleState: false,
                          errorBuilder: (_, _) => const SizedBox.shrink(),
                        ),

                        // 스캔 프레임
                        if (_cameraReady)
                          Center(
                            child: AnimatedBuilder(
                              animation: _pulseAnim,
                              builder: (_, __) => Container(
                                width: 220,
                                height: 220,
                                decoration: BoxDecoration(
                                  border: Border.all(
                                    color: Colors.white.withOpacity(
                                      _pulseAnim.value,
                                    ),
                                    width: 2.5,
                                  ),
                                  borderRadius: BorderRadius.circular(16),
                                ),
                                child: Stack(
                                  children: [
                                    _corner(0, 0, true, true),
                                    _corner(0, 0, true, false),
                                    _corner(0, 0, false, true),
                                    _corner(0, 0, false, false),
                                  ],
                                ),
                              ),
                            ),
                          ),

                        // 스캔 가이드 텍스트
                        if (_cameraReady)
                          Positioned(
                            bottom: 24,
                            left: 0,
                            right: 0,
                            child: Center(
                              child: Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 18,
                                  vertical: 10,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.black.withOpacity(0.55),
                                  borderRadius: BorderRadius.circular(20),
                                ),
                                child: const Text(
                                  'QR 코드를 네모 안에 맞춰주세요',
                                  textAlign: TextAlign.center,
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ),
                            ),
                          ),

                        // 로딩 오버레이
                        if (!_cameraReady)
                          Container(
                            color: Colors.black.withOpacity(0.7),
                            child: Center(
                              child: SingleChildScrollView(
                                child: Column(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Container(
                                      width: 72,
                                      height: 72,
                                      decoration: BoxDecoration(
                                        color: Colors.white.withOpacity(0.1),
                                        shape: BoxShape.circle,
                                        border: Border.all(
                                          color: Colors.white.withOpacity(0.2),
                                        ),
                                      ),
                                      child: const Padding(
                                        padding: EdgeInsets.all(18),
                                        child: CircularProgressIndicator(
                                          color: Colors.white,
                                          strokeWidth: 2.5,
                                        ),
                                      ),
                                    ),
                                    const SizedBox(height: 20),
                                    const Text(
                                      '카메라 준비 중',
                                      style: TextStyle(
                                        color: Colors.white,
                                        fontSize: 16,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ),

                  // ── 결과 패널 ──
                  Expanded(
                    flex: 4,
                    child: Container(
                      width: double.infinity,
                      decoration: const BoxDecoration(
                        color: AppColors.surface,
                        borderRadius: BorderRadius.vertical(
                          top: Radius.circular(24),
                        ),
                      ),
                      child: _buildGuideView(),
                    ),
                  ),
                ],
              ),
            ),
          ),
          if (_phase == _ScanPhase.analyzing) _buildProgressView(),
          if (_phase == _ScanPhase.result || _phase == _ScanPhase.error)
            ColoredBox(
              color: AppColors.surface,
              child: _phase == _ScanPhase.error
                  ? _buildErrorView()
                  : _buildResultView(),
            ),
        ],
      ),
    );
  }

  // 모서리 장식
  Widget _corner(double top, double left, bool isTop, bool isLeft) {
    return Positioned(
      top: isTop ? 0 : null,
      bottom: isTop ? null : 0,
      left: isLeft ? 0 : null,
      right: isLeft ? null : 0,
      child: Container(
        width: 24,
        height: 24,
        decoration: BoxDecoration(
          border: Border(
            top: isTop
                ? const BorderSide(color: AppColors.accent, width: 3)
                : BorderSide.none,
            bottom: !isTop
                ? const BorderSide(color: AppColors.accent, width: 3)
                : BorderSide.none,
            left: isLeft
                ? const BorderSide(color: AppColors.accent, width: 3)
                : BorderSide.none,
            right: !isLeft
                ? const BorderSide(color: AppColors.accent, width: 3)
                : BorderSide.none,
          ),
        ),
      ),
    );
  }

  // ── 가이드 뷰 ─────────────────────────────────────────
  Widget _buildGuideView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 4,
            height: 20,
            decoration: BoxDecoration(
              color: AppColors.accent,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'QR 코드를 스캔하세요',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.w700,
              color: AppColors.textPrim,
              letterSpacing: -0.5,
            ),
          ),
          const SizedBox(height: 10),
          const Text(
            'QR 코드의 내용을 분석하여\n피싱 여부와 위험도를 확인합니다.',
            style: TextStyle(
              fontSize: 14,
              color: AppColors.textSec,
              height: 1.6,
            ),
          ),
          const SizedBox(height: 24),
          Row(children: [_infoChip(Icons.speed_rounded, '실시간 분석')]),
        ],
      ),
    );
  }

  Widget _infoChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: AppColors.surfaceSub,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppColors.border),
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
              fontWeight: FontWeight.w500,
              color: AppColors.textSec,
            ),
          ),
        ],
      ),
    );
  }

  // ── 에러 뷰 ──────────────────────────────────────────
  Widget _buildErrorView() {
    return SingleChildScrollView(
      key: const Key('analysis-error-scroll'),
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(
                Icons.error_outline_rounded,
                color: AppColors.danger,
                size: 22,
              ),
              const SizedBox(width: 8),
              const Flexible(
                child: Text(
                  '오류 발생',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    color: AppColors.danger,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            _errorMessage ?? '',
            style: const TextStyle(
              fontSize: 13,
              color: AppColors.textSec,
              height: 1.6,
            ),
          ),
        ],
      ),
    );
  }

  // ── 결과 뷰 ──────────────────────────────────────────
  Widget _buildResultView() {
    return AnalysisResultView(result: _result!);
  }

  Widget _buildProgressView() => const Center(
    child: SingleChildScrollView(
      padding: EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircularProgressIndicator(color: Colors.white),
          SizedBox(height: 20),
          Text(
            'QR 내용 분석 중',
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.w600,
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
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
          ),
        ),
        style: FilledButton.styleFrom(
          backgroundColor: AppColors.accent,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
    );
  }
}
