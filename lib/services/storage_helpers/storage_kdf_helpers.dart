import 'dart:math';
import 'package:cryptography/cryptography.dart';
import '../../services/crypto_service.dart';
import 'storage_constants.dart' as sc;
import 'storage_crypto_helpers.dart' as sh;
Future<({int memoryKb, int iterations, int parallelism})> calibrateArgon2(
  CryptoService cryptoService, {
  required int targetMs,
}) async {
  final testSalt = sh.secureRandomBytes(cryptoService.saltLength);
  const testPassword = 'qsv-calibration';
  int iterations = max(sc.minIterations, 1);
  int memoryKb = max(sc.minMemoryKb, sc.slowKdfMemoryKb ~/ 2);
  int parallelism = sc.minParallelism;
  Duration took;
  do {
    final sw = Stopwatch()..start();
    await cryptoService.deriveKeyFromPassword(
      password: testPassword,
      salt: testSalt,
      kdf: 'argon2id',
      iterations: iterations,
      memoryKb: memoryKb,
      parallelism: parallelism,
    );
    sw.stop();
    took = sw.elapsed;
    if (took.inMilliseconds < targetMs) {
      iterations = (iterations * 2).clamp(sc.minIterations, 1 << 24);
      if (iterations > 8 && took.inMilliseconds < targetMs / 4) {
        memoryKb = (memoryKb * 2).clamp(sc.minMemoryKb, sc.slowKdfMemoryKb);
      }
    }
  } while (took.inMilliseconds < targetMs && iterations < (1 << 20));
  return (memoryKb: memoryKb, iterations: iterations, parallelism: parallelism);
}
Future<SecretKey> deriveFastKeyArgon2(
  CryptoService cryptoService,
  String password,
  List<int> salt, {
  required int memoryKb,
  required int iterations,
  required int parallelism,
}) async {
  return cryptoService.deriveKeyFromPassword(
    password: password,
    salt: salt,
    kdf: 'argon2id',
    iterations: iterations,
    memoryKb: memoryKb,
    parallelism: parallelism,
  );
}
