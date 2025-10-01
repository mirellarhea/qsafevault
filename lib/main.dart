import 'package:flutter/material.dart';
import '/pages/landing_page.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import 'platforms/windows.dart';
import 'dart:io';
void main() {
  WidgetsFlutterBinding.ensureInitialized();

  final cryptoService = CryptoService();
  final storageService = StorageService(cryptoService);

  //windows specific setup
  setupWindowsWindow();

  runApp(MyApp(storage: storageService, cryptoService: cryptoService));
}

class MyApp extends StatelessWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const MyApp({Key? key, required this.storage, required this.cryptoService}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    Widget page = LandingPage(storage: storage, cryptoService: cryptoService);
    if (Platform.isWindows) {
      page = wrapWithWindowsBorder(page);
    }
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Q-Safe Vault',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: LandingPage(storage: storage, cryptoService: cryptoService),
      builder: (context, child) {
        if (Platform.isWindows && child != null) {
          return wrapWithWindowsBorder(child);
        }
        return child!;
      },
    );
  }
}
