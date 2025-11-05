import 'dart:async';
import 'package:flutter/services.dart';

class TorService {
  static const MethodChannel _ch = MethodChannel('qsafevault/tor');

  Future<({String onion, int socksPort})> start({
    required int localSyncPort,
    int? socksPort,
  }) async {
    final args = {
      'localSyncPort': localSyncPort,
      if (socksPort != null) 'socksPort': socksPort,
    };
    final res = await _ch.invokeMethod<Map>('startTor', args);
    if (res == null) {
      throw Exception('Tor start failed (no response)');
    }
    final onion = (res['onion'] ?? '') as String;
    final socks = (res['socksPort'] ?? 0) as int;
    if (onion.isEmpty || socks <= 0) {
      throw Exception('Invalid Tor result: $res');
    }
    return (onion: onion, socksPort: socks);
  }
}
