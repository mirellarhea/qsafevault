import 'package:flutter/material.dart';
import '/pages/landing_page.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final cryptoService = CryptoService();
  final storageService = StorageService(cryptoService);
  runApp(MyApp(storage: storageService, cryptoService: cryptoService));
}

class MyApp extends StatelessWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const MyApp({Key? key, required this.storage, required this.cryptoService}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Password Manager (demo)',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: LandingPage(storage: storage, cryptoService: cryptoService),
    );
  }
}
