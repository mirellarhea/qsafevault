import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'dart:isolate';

import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:path/path.dart' as path;
import 'package:flutter/foundation.dart';

import 'package:qsafevault/services/crypto_service.dart';
import 'package:qsafevault/services/storage_service.dart';

void main() {
  late CryptoService cryptoService;
  late StorageService storage;
  late Directory tempDir;
  final random = Random.secure();

  setUp(() async {
    cryptoService = CryptoService();
    // Important: disable secure storage for deterministic file-based tests.
    storage = StorageService(cryptoService, useSecureStorage: false);
    tempDir = await Directory.systemTemp.createTemp('storage_test_');
  });

  tearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  void logTime(String label, Stopwatch sw) {
    debugPrint('$label: ${sw.elapsedMilliseconds} ms');
  }

  String randomPassword([int length = 12]) {
    const chars =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*()_+-=';
    return List.generate(length, (_) => chars[random.nextInt(chars.length)])
        .join();
  }

  test('Create and open DB with correct password', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'myStrongPassword';

    final swCreate = Stopwatch()..start();
    await storage.createEmptyDb(folderPath: folderPath, password: password);
    swCreate.stop();
    logTime('DB creation', swCreate);

    final swOpen = Stopwatch()..start();
    final result =
        await storage.openDb(folderPath: folderPath, password: password);
    swOpen.stop();
    logTime('DB open', swOpen);

    expect(result.plaintext, jsonEncode(<dynamic>[]));
    expect(result.key, isA<SecretKey>());
  });

  test('Open DB with wrong password fails', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'correctPassword';
    final wrongPassword = 'wrongPassword';

    await storage.createEmptyDb(folderPath: folderPath, password: password);

    final sw = Stopwatch()..start();
    expect(
      () async =>
          await storage.openDb(folderPath: folderPath, password: wrongPassword),
      throwsA(predicate((e) => e.toString().contains('Invalid password'))),
    );
    sw.stop();
    logTime('Open DB with wrong password', sw);
  });

  test('Derived key deletion and fallback', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'deleteKeyTest';

    await storage.createEmptyDb(folderPath: folderPath, password: password);

    final first =
        await storage.openDb(folderPath: folderPath, password: password);
    await storage.deleteDerivedKey(folderPath);

    final second =
        await storage.openDb(folderPath: folderPath, password: password);
    expect(second.plaintext, first.plaintext);
  });

  test('Corrupted derived key triggers slow derive', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'corruptTestPass';

    await storage.createEmptyDb(folderPath: folderPath, password: password);

    final derivedKeyFile =
        File(path.join(folderPath, StorageService.derivedKeyFileName));
    await derivedKeyFile.writeAsBytes(List<int>.generate(32, (_) => 42));

    expect(
      () async =>
          await storage.openDb(folderPath: folderPath, password: password),
      throwsA(predicate((e) =>
          e.toString().contains('Invalid password') ||
          e.toString().contains('corrupted derived key'))),
    );
  });

  test('Save DB and create backups', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'backupTest';

    await storage.createEmptyDb(folderPath: folderPath, password: password);
    final db = await storage.openDb(folderPath: folderPath, password: password);

    final newContent = jsonEncode([
      {'item': 'backup'}
    ]);
    await storage.saveDb(
        folderPath: folderPath, key: db.key, jsonDb: newContent);

    final metaFile = File(path.join(folderPath, StorageService.metaFileName));
    final meta = jsonDecode(await metaFile.readAsString());
    final parts = meta['parts'] as int;
    bool allBackupsExist = true;

    for (var i = 0; i < parts; i++) {
      final backupFile = File(path.join(folderPath,
          '${StorageService.baseEncryptedName}.part${i + 1}${StorageService.backupSuffix}'));
      if (!await backupFile.exists()) allBackupsExist = false;
    }
    expect(allBackupsExist, true);
  });

  test('Cleanup backups removes .bak files', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'cleanupBackupsPass';

    await storage.createEmptyDb(folderPath: folderPath, password: password);
    final db = await storage.openDb(folderPath: folderPath, password: password);

    await storage.saveDb(
        folderPath: folderPath, key: db.key, jsonDb: jsonEncode([]));

    // Ensure at least one .bak exists
    final bakGlob = Directory(folderPath)
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith(StorageService.backupSuffix))
        .toList();
    expect(bakGlob.isNotEmpty, true);

    await storage.cleanupBackups(folderPath);

    final remainingBak = Directory(folderPath)
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith(StorageService.backupSuffix))
        .toList();
    expect(remainingBak.isEmpty, true);
  });

  test('Reading non-existent DB folder throws', () async {
    final invalidFolder = Directory('${tempDir.path}/invalid');
    expect(() async => await storage.validateDbFolder(invalidFolder.path),
        throwsException);
  });

  test('isDirectoryEmpty works for empty and non-empty dirs', () async {
    final emptyDir = Directory('${tempDir.path}/empty');
    await emptyDir.create();
    final nonEmptyDir = Directory('${tempDir.path}/nonempty');
    await nonEmptyDir.create();
    await File('${nonEmptyDir.path}/file.txt').writeAsString('test');

    expect(await storage.isDirectoryEmpty(emptyDir.path), true);
    expect(await storage.isDirectoryEmpty(nonEmptyDir.path), false);
  });

  test('Partial DB parts missing throws exception', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'partialParts';

    await storage.createEmptyDb(folderPath: folderPath, password: password);
    final db = await storage.openDb(folderPath: folderPath, password: password);

    final partFile =
        File('${folderPath}/${StorageService.baseEncryptedName}.part1');
    if (await partFile.exists()) await partFile.delete();

    expect(
        () async =>
            await storage.openDb(folderPath: folderPath, password: password),
        throwsException);
  });

  test('createEmptyDbIsolateEntry executes in isolate', () async {
    final folderPath = await storage.ensureEmptyOrPwdbSubdir(tempDir.path);
    final password = 'isolatePass';

    final receivePort = ReceivePort();
    await Isolate.spawn(StorageService.createEmptyDbIsolateEntry,
        [receivePort.sendPort, folderPath, password, 5, 16, 1, 1, 1]);
    final result = await receivePort.first;
    expect(result, null);
  });
}
