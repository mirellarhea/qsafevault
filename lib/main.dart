import 'package:flutter/material.dart';
import '/pages/landing_page.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import 'platforms/windows.dart';
import 'dart:io';
import 'package:qsafevault/services/theme_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ThemeService.instance.init();
  final cryptoService = CryptoService();
  final storageService = StorageService(cryptoService);
  setupWindowsWindow();
  runApp(MyApp(storage: storageService, cryptoService: cryptoService));
}

class MyApp extends StatelessWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const MyApp({Key? key, required this.storage, required this.cryptoService})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    Widget page = LandingPage(storage: storage, cryptoService: cryptoService);
    if (Platform.isWindows) {
      page = wrapWithWindowsBorder(page);
    }
    return StreamBuilder<AppThemeMode>(
      stream: ThemeService.instance.stream,
      initialData: ThemeService.instance.mode,
      builder: (context, snapshot) {
        final m = snapshot.data ?? AppThemeMode.system;
        final mode = switch (m) {
          AppThemeMode.light => ThemeMode.light,
          AppThemeMode.dark => ThemeMode.dark,
          _ => ThemeMode.system,
        };
        return MaterialApp(
          debugShowCheckedModeBanner: false,
          title: 'Q-Safe Vault',
          theme: ThemeData.light(),
          darkTheme: ThemeData.dark(),
          themeMode: mode,
          home: LandingPage(storage: storage, cryptoService: cryptoService),
          builder: (context, child) {
            if (Platform.isWindows && child != null) {
              return wrapWithWindowsBorder(child);
            }
            return child!;
          },
        );
      },
    );
  }
}
