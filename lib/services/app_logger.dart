import 'dart:async';
import 'dart:io';

class AppLogger {
  AppLogger._();
  static final AppLogger instance = AppLogger._();

  IOSink? _sink;
  String? _dirPath;
  String get logFileName => 'sync.log';
  String? get currentDir => _dirPath;

  Future<bool> setDirectory(String dirPath) async {
    try {
      if (_dirPath != null && _dirPath != dirPath) {
        await _sink?.flush();
        await _sink?.close();
        _sink = null;
      }
      _dirPath = dirPath;
      final dir = Directory(dirPath);
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
      final file = File('${dir.path}${Platform.pathSeparator}$logFileName');
      _sink ??= file.openWrite(mode: FileMode.append);
      _sink!.writeln('--- ${DateTime.now().toIso8601String()} START (${Platform.operatingSystem}) ---');
      return true;
    } catch (_) {
      _dirPath = null;
      try {
        await _sink?.close();
      } catch (_) {}
      _sink = null;
      return false;
    }
  }

  void write(String line) {
    try {
      print(line);
      _sink?.writeln(line);
    } catch (_) {}
  }

  Future<void> close() async {
    try {
      await _sink?.flush();
      await _sink?.close();
    } catch (_) {}
    _sink = null;
  }
}
