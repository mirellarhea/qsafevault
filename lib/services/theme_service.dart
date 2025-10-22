import 'dart:async';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
enum AppThemeMode { system, light, dark }
class ThemeService {
  ThemeService._();
  static final ThemeService instance = ThemeService._();
  final _controller = StreamController<AppThemeMode>.broadcast();
  AppThemeMode _mode = AppThemeMode.system;
  Future<File> _file() async {
    final dir = await getApplicationSupportDirectory();
    return File('${dir.path}/qsv_theme_mode.txt');
  }
  Future<void> init() async {
    try {
      final f = await _file();
      if (await f.exists()) {
        final raw = (await f.readAsString()).trim();
        _mode = _fromString(raw) ?? AppThemeMode.system;
      } else {
        _mode = AppThemeMode.system;
      }
    } catch (_) {
      _mode = AppThemeMode.system;
    }
    _controller.add(_mode);
  }
  AppThemeMode get mode => _mode;
  Stream<AppThemeMode> get stream => _controller.stream;
  Future<void> setMode(AppThemeMode mode) async {
    _mode = mode;
    try {
      final f = await _file();
      await f.create(recursive: true);
      await f.writeAsString(_toString(mode), flush: true);
    } catch (_) {}
    _controller.add(_mode);
  }
  Future<void> toggleLightDark() async {
    final next = (_mode == AppThemeMode.dark) ? AppThemeMode.light : AppThemeMode.dark;
    await setMode(next);
  }
  String _toString(AppThemeMode m) {
    switch (m) {
      case AppThemeMode.system:
        return 'system';
      case AppThemeMode.light:
        return 'light';
      case AppThemeMode.dark:
        return 'dark';
    }
  }
  AppThemeMode? _fromString(String? s) {
    switch (s) {
      case 'system':
        return AppThemeMode.system;
      case 'light':
        return AppThemeMode.light;
      case 'dark':
        return AppThemeMode.dark;
      default:
        return null;
    }
  }
  void dispose() {
    _controller.close();
  }
}
