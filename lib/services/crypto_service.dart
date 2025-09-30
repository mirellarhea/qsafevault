import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class CryptoService {
  final AesGcm _aes = AesGcm.with256bits();
  final int _nonceLength = 12;
  final int saltLength = 16;

  int get nonceLength => _nonceLength;
  String get cipherName => 'aes-256-gcm';

  Future<SecretKey> deriveKeyFromPassword({
    required String password,
    required List<int> salt,
    String kdf = 'pbkdf2',
    int iterations = 20000,
    int memoryKb = 64, //return to 512 next time
    int parallelism = 2,
  }) async {
    if (kdf.toLowerCase() == 'argon2id') {
      final argon2 = Argon2id(
        memory: memoryKb,
        iterations: iterations,
        parallelism: parallelism,
        hashLength: 32,
      );
      final secretKey = await argon2.deriveKey(
        secretKey: SecretKey(utf8.encode(password)),
        nonce: salt,
      );
      return secretKey;
    } else {
      final pbkdf2 = Pbkdf2(
        macAlgorithm: Hmac.sha256(),
        iterations: iterations,
        bits: 256,
      );
      final secretKey = await pbkdf2.deriveKeyFromPassword(
        password: password,
        nonce: salt,
      );
      return secretKey;
    }
  }

  Future<Uint8List> encryptUtf8(SecretKey key, String plaintext) async {
    final nonce = _aes.newNonce();
    final secretBox = await _aes.encrypt(
      utf8.encode(plaintext),
      secretKey: key,
      nonce: nonce,
    );
    final out = BytesBuilder(copy: false);
    out.add(secretBox.nonce);
    out.add(secretBox.cipherText);
    out.add(secretBox.mac.bytes);
    return Uint8List.fromList(out.toBytes());
  }

  Future<String> decryptUtf8(SecretKey key, Uint8List data) async {
    final nonceLen = _nonceLength;
    final macLen = 16;
    if (data.length < nonceLen + macLen) {
      throw Exception('Invalid encrypted blob size');
    }
    final nonce = data.sublist(0, nonceLen);
    final macBytes = data.sublist(data.length - macLen);
    final cipherText = data.sublist(nonceLen, data.length - macLen);
    final secretBox = SecretBox(
      cipherText,
      nonce: nonce,
      mac: Mac(macBytes),
    );
    final clear = await _aes.decrypt(
      secretBox,
      secretKey: key,
    );
    return utf8.decode(clear);
  }
}