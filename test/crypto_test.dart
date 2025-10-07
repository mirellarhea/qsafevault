import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:qsafevault/services/crypto_service.dart';

void main() {
  late CryptoService crypto;
  final random = Random.secure();

  setUp(() {
    crypto = CryptoService();
  });

  String randomPassword([int length = 12]) {
    const chars =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*()_+-=';
    return List.generate(length, (_) => chars[random.nextInt(chars.length)])
        .join();
  }

  List<int> randomSalt([int length = 16]) =>
      List.generate(length, (_) => random.nextInt(256));

  test('deriveKeyFromPassword returns a SecretKey for Argon2id', () async {
    final password = randomPassword();
    final salt = randomSalt();

    final key = await crypto.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'argon2id',
      iterations: 1,
      memoryKb: 16,
      parallelism: 1,
    );

    expect(key, isA<SecretKey>());
    final keyBytes = await key.extractBytes();
    expect(keyBytes.length, 32);
  });

  test('deriveKeyFromPassword returns a SecretKey for PBKDF2', () async {
    final password = randomPassword();
    final salt = randomSalt();

    final key = await crypto.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'pbkdf2',
      iterations: 10,
    );

    expect(key, isA<SecretKey>());
    final keyBytes = await key.extractBytes();
    expect(keyBytes.length, 32);
  });

  test('encryptUtf8 and decryptUtf8 round-trip works', () async {
    final password = randomPassword();
    final salt = randomSalt();
    final key =
        await crypto.deriveKeyFromPassword(password: password, salt: salt);

    final plaintext = 'Hello, world!';
    final encrypted = await crypto.encryptUtf8(key, plaintext);
    expect(encrypted.length, greaterThan(plaintext.length));

    final decrypted = await crypto.decryptUtf8(key, encrypted);
    expect(decrypted, plaintext);
  });

  test('decryptUtf8 with wrong key fails', () async {
    final key1 = await crypto.deriveKeyFromPassword(
        password: 'password1', salt: randomSalt());
    final key2 = await crypto.deriveKeyFromPassword(
        password: 'password2', salt: randomSalt());

    final plaintext = 'Secret message';
    final encrypted = await crypto.encryptUtf8(key1, plaintext);

    expect(() async => await crypto.decryptUtf8(key2, encrypted),
        throwsA(isA<Exception>()));
  });

  test('encryptUtf8 handles empty string', () async {
    final key = await crypto.deriveKeyFromPassword(
        password: 'test', salt: randomSalt());

    final encrypted = await crypto.encryptUtf8(key, '');
    expect(encrypted.length, greaterThan(0));

    final decrypted = await crypto.decryptUtf8(key, encrypted);
    expect(decrypted, '');
  });

  test('decryptUtf8 throws on invalid blob length', () async {
    final key = await crypto.deriveKeyFromPassword(
        password: 'test', salt: randomSalt());

    final invalidData = Uint8List.fromList([1, 2, 3]);
    expect(() async => await crypto.decryptUtf8(key, invalidData),
        throwsA(isA<Exception>()));
  });

  test('nonceLength and cipherName getters', () {
    expect(crypto.nonceLength, 12);
    expect(crypto.cipherName, 'aes-256-gcm');
  });

  test('Multiple encrypt/decrypt round-trips produce unique ciphertexts',
      () async {
    final key = await crypto.deriveKeyFromPassword(
        password: 'unique', salt: randomSalt());
    final plaintext = 'Repeated test string';

    final encrypted1 = await crypto.encryptUtf8(key, plaintext);
    final encrypted2 = await crypto.encryptUtf8(key, plaintext);

    expect(encrypted1, isNot(encrypted2));

    final decrypted1 = await crypto.decryptUtf8(key, encrypted1);
    final decrypted2 = await crypto.decryptUtf8(key, encrypted2);

    expect(decrypted1, plaintext);
    expect(decrypted2, plaintext);
  });
}
