import 'dart:math';

class SyncConfig {
  final String baseUrl;
  final Duration httpTimeout;
  final Duration pollInterval;
  final Duration pollMaxWait;
  final Duration backoffMax;
  final List<String> turnUrls;
  final String? turnUsername;
  final String? turnCredential;

  const SyncConfig({
    required this.baseUrl,
    this.httpTimeout = const Duration(seconds: 8),
    this.pollInterval = const Duration(milliseconds: 800),
    this.pollMaxWait = const Duration(seconds: 180),
    this.backoffMax = const Duration(seconds: 3),
    this.turnUrls = const [],
    this.turnUsername,
    this.turnCredential,
  });

  static SyncConfig defaults() => SyncConfig(
        baseUrl: const String.fromEnvironment(
          'QSV_SYNC_BASEURL',
          defaultValue: 'https://qsafevault-server.vercel.app',
        ),
        turnUrls: const String.fromEnvironment('QSV_TURN_URLS', defaultValue: '')
            .split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList(),
        turnUsername: const String.fromEnvironment('QSV_TURN_USERNAME', defaultValue: '')
            .trim(),
        turnCredential: const String.fromEnvironment('QSV_TURN_CREDENTIAL', defaultValue: '')
            .trim(),
      );
}

Duration jitter(Duration base, {int msJitter = 150}) {
  final r = Random.secure().nextInt(msJitter * 2) - msJitter;
  final t = base + Duration(milliseconds: r);
  return t.isNegative ? Duration.zero : t;
}
