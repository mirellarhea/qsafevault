import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/export.dart';

class HybridEncryption {
  /// Derive AES key from password using PBKDF2 + HMAC-SHA256
  static Uint8List deriveKey(String password, Uint8List salt,
      {int iterations = 100000, int keyLength = 32}) {
    final derivator = KeyDerivator('SHA-256/HMAC/PBKDF2');
    derivator.init(Pbkdf2Parameters(salt, iterations, keyLength));
    return derivator.process(Uint8List.fromList(utf8.encode(password)));
  }

  /// Encrypt database JSON using AES-GCM (requires IV)
  static Map<String, Uint8List> encryptDatabase(Uint8List key, String jsonData) {
    final aesKey = encrypt.Key(key);
    final iv = encrypt.IV.fromSecureRandom(12); // 96-bit IV
    final encrypter = encrypt.Encrypter(encrypt.AES(aesKey, mode: encrypt.AESMode.gcm));
    final encrypted = encrypter.encrypt(jsonData, iv: iv);
    return {
      'cipherBytes': Uint8List.fromList(encrypted.bytes),
      'iv': Uint8List.fromList(iv.bytes),
    };
  }

  /// Decrypt database JSON using AES-GCM
  static String decryptDatabase(Uint8List key, Uint8List cipherBytes, Uint8List ivBytes) {
    final aesKey = encrypt.Key(key);
    final encrypter = encrypt.Encrypter(encrypt.AES(aesKey, mode: encrypt.AESMode.gcm));
    final encrypted = encrypt.Encrypted(cipherBytes);
    final decryptedBytes = encrypter.decryptBytes(encrypted, iv: encrypt.IV(ivBytes));
    return utf8.decode(decryptedBytes);
  }

  static List<Uint8List> splitChunks(Uint8List data, int numChunks) {
    final chunkSize = (data.length / numChunks).ceil();
    final chunks = <Uint8List>[];
    for (int i = 0; i < data.length; i += chunkSize) {
      final end = (i + chunkSize < data.length) ? i + chunkSize : data.length;
      chunks.add(Uint8List.fromList(data.sublist(i, end)));
    }
    return chunks;
  }

  static Uint8List mergeChunks(List<Uint8List> chunks) {
    final combined = <int>[];
    for (final chunk in chunks) combined.addAll(chunk);
    return Uint8List.fromList(combined);
  }

  static Uint8List generateSalt([int length = 16]) {
    final rnd = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rnd.nextInt(256)));
  }

  static List<Uint8List> shuffleChunks(List<Uint8List> chunks, String password, Uint8List salt) {
    final seed = password.codeUnits.fold<int>(0, (prev, el) => prev + el) +
        salt.fold<int>(0, (prev, el) => prev + el);
    final rng = Random(seed);
    final shuffled = List<Uint8List>.from(chunks);
    for (int i = shuffled.length - 1; i > 0; i--) {
      final j = rng.nextInt(i + 1);
      final tmp = shuffled[i];
      shuffled[i] = shuffled[j];
      shuffled[j] = tmp;
    }
    return shuffled;
  }
}
