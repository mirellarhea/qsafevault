import 'dart:math';

class SyncConfig {
  final String baseUrl;
  final Duration httpTimeout;
  final Duration pollInterval;
  final Duration pollMaxWait;
  final Duration backoffMax;

  const SyncConfig({
    required this.baseUrl,
    this.httpTimeout = const Duration(seconds: 8),
    this.pollInterval = const Duration(milliseconds: 800),
    this.pollMaxWait = const Duration(seconds: 180),
    this.backoffMax = const Duration(seconds: 3),
  });

  static SyncConfig defaults() => SyncConfig(
        baseUrl: const String.fromEnvironment(
          'QSV_SYNC_BASEURL',
          defaultValue: 'https://qsafevault-server.vercel.app',
        ),
      );
}

Duration jitter(Duration base, {int msJitter = 150}) {
  final r = Random.secure().nextInt(msJitter * 2) - msJitter;
  final t = base + Duration(milliseconds: r);
  return t.isNegative ? Duration.zero : t;
}
