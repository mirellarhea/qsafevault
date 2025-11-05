import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/sync_config.dart';

class DeviceRegistryClient {
  final String base;
  final http.Client _http;

  DeviceRegistryClient({String? baseUrl, http.Client? httpClient})
      : base = (baseUrl ?? SyncConfig.defaults().baseUrl).replaceAll(RegExp(r'/+$'), ''),
        _http = httpClient ?? http.Client();

  Uri _u(String path, [Map<String, String>? q]) {
    final p = path.startsWith('/') ? path : '/$path';
    final u = Uri.parse('$base$p');
    return q == null || q.isEmpty ? u : u.replace(queryParameters: q);
  }

  Future<void> register({
    required String userId,
    required String deviceId,
    required String onionHost,
    int port = 5000,
    int ttlSec = 604800,
  }) async {
    final uri = _u('/api/v1/devices');
    final r = await _http.post(uri,
        headers: {'content-type': 'application/json'},
        body: jsonEncode({
          'userId': userId,
          'deviceId': deviceId,
          'onion': onionHost,
          'port': port,
          'ttlSec': ttlSec,
        }));
    if (r.statusCode != 200) {
      throw Exception('device register failed (${r.statusCode}): ${r.body}');
    }
  }

  Future<List<({String deviceId, String onion, int port})>> list(String userId) async {
    final uri = _u('/api/v1/devices/$userId');
    final r = await _http.get(uri);
    if (r.statusCode != 200) {
      throw Exception('device list failed (${r.statusCode}): ${r.body}');
    }
    final obj = jsonDecode(r.body) as Map<String, dynamic>;
    final arr = (obj['devices'] as List?) ?? const [];
    return arr.map<({String deviceId, String onion, int port})>((e) {
      final m = e as Map<String, dynamic>;
      return (deviceId: m['deviceId'] as String, onion: m['onion'] as String, port: (m['port'] as num).toInt());
    }).toList();
  }
}
