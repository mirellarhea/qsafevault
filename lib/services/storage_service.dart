import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'dart:isolate';
import 'dart:async';
import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:synchronized/synchronized.dart';
import 'package:qsafevault/services/secure_storage.dart';
import 'crypto_service.dart';
import 'storage_helpers/storage_constants.dart' as sc;
import 'storage_helpers/storage_crypto_helpers.dart' as sh;
import 'storage_helpers/storage_file_helpers.dart' as fh;
import 'storage_helpers/storage_kdf_helpers.dart' as kh;
class StorageService {
  final CryptoService cryptoService;
  final bool allowDiskWrappedKeyFallback;
  StorageService(this.cryptoService, {this.allowDiskWrappedKeyFallback = false});
  final _lock = Lock();
  final SecureStorage _osSecure = SecureStorage();
  Future<String> pickDirectoryWithFallback() async {
    try {
      final selected = await FilePicker.platform.getDirectoryPath();
      if (selected != null && selected.isNotEmpty) return selected;
    } catch (_) {}
    final appDoc = await getApplicationDocumentsDirectory();
    final dir = Directory('${appDoc.path}/PasswordManager');
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir.path;
  }
  Future<String?> pickVaultFolderForOpen() async {
    try {
      final res = await FilePicker.platform.pickFiles(
        dialogTitle: 'Open Vault - select pwdb.meta.json',
        type: FileType.custom,
        allowedExtensions: ['json'],
        allowMultiple: false,
      );
      final path = res?.files.single.path;
      if (path == null) return null;
      final name = path.split(Platform.pathSeparator).last;
      if (name != sc.metaFileName) {
        throw Exception('Please select the file "${sc.metaFileName}".');
      }
      final folder = Directory(path).parent.path;
      if (!await File('$folder/${sc.metaFileName}').exists()) {
        throw Exception('Selected file is not a valid vault metadata file.');
      }
      return folder;
    } catch (e) {
      rethrow;
    }
  }
  Future<String> ensureEmptyOrPwdbSubdir(String folderPath) async {
    final dir = Directory(folderPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      return dir.path;
    }
    final contents = await dir.list(followLinks: false).toList();
    if (contents.isEmpty) {
      return dir.path;
    }
    final pwdbDir = Directory('${dir.path}/pwdb');
    if (!await pwdbDir.exists()) {
      await pwdbDir.create(recursive: true);
    }
    return pwdbDir.path;
  }
  Future<String> validateDbFolder(String folderPath) async {
    final metaFile = File('$folderPath/${sc.metaFileName}');
    if (await metaFile.exists()) return folderPath;
    final alt = Directory('$folderPath/pwdb');
    final altMeta = File('${alt.path}/${sc.metaFileName}');
    if (await altMeta.exists()) return alt.path;
    throw Exception('Invalid folder: missing ${sc.metaFileName}');
  }
  Future<bool> isDirectoryEmpty(String path) async {
    final dir = Directory(path);
    if (!await dir.exists()) return true;
    try {
      return await dir.list(followLinks: false).isEmpty;
    } catch (_) {
      return true;
    }
  }
  Future<void> createEmptyDb({
    required String folderPath,
    required String password,
    int parts = 3,
    int memoryKb = sc.slowKdfMemoryKb,
    int iterations = sc.slowKdfIterations,
    int parallelism = sc.slowKdfParallelism,
  }) async {
    if (password.isEmpty) throw ArgumentError('Password cannot be empty.');
    if (parts <= 0) throw ArgumentError('Parts must be > 0');
    folderPath = await ensureEmptyOrPwdbSubdir(folderPath);
    if (memoryKb <= 0 || iterations <= 0) {
      final tuned = await kh.calibrateArgon2(cryptoService, targetMs: sc.slowTargetMs);
      memoryKb = max(tuned.memoryKb, sc.minMemoryKb);
      iterations = max(tuned.iterations, sc.minIterations);
      parallelism = max(tuned.parallelism, sc.minParallelism);
    }
    final salt = sh.secureRandomBytes(cryptoService.saltLength);
    final strongKey = await cryptoService.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'argon2id',
      iterations: iterations,
      memoryKb: memoryKb,
      parallelism: parallelism,
    );
    final initialJson = jsonEncode(<dynamic>[]);
    final encrypted = await cryptoService.encryptUtf8(strongKey, initialJson);
    sh.zeroBytes(Uint8List.fromList(utf8.encode(initialJson)));
    final fastSalt = sh.secureRandomBytes(sc.fastKdfSaltLen);
    final fastTuned = await kh.calibrateArgon2(cryptoService, targetMs: sc.fastTargetMs);
    final fIterations = max(fastTuned.iterations, sc.minIterations);
    final fMemoryKb = max(fastTuned.memoryKb, sc.minMemoryKb);
    final fParallelism = max(fastTuned.parallelism, sc.minParallelism);
    final fastKey = await kh.deriveFastKeyArgon2(
      cryptoService,
      password,
      fastSalt,
      memoryKb: fMemoryKb,
      iterations: fIterations,
      parallelism: fParallelism,
    );
    final firstWrapNonce = await sh.computeWrapNonce(fastKey, 1);
    final wrapped = await sh.wrapKeyWithAesGcm(
      wrappingKey: fastKey,
      toWrap: await strongKey.extractBytes(),
      nonce: firstWrapNonce,
    );
    final verifier = await sh.makeVerifier(strongKey);
    final fastMeta = {
      'kdf': 'argon2id',
      'iterations': fIterations,
      'memoryKb': fMemoryKb,
      'parallelism': fParallelism,
      'salt': base64Encode(fastSalt),
    };
    final fastSig = await sh.signFastParams(strongKey, fastMeta);
    await _lock.synchronized(() async {
      await fh.writePartsAtomic(folderPath, encrypted, parts);
      final meta = {
        'version': 3,
        'kdf': 'argon2id',
        'memoryKb': memoryKb,
        'iterations': iterations,
        'parallelism': parallelism,
        'salt': base64Encode(salt),
        'cipher': cryptoService.cipherName,
        'nonceLength': cryptoService.nonceLength,
        'parts': parts,
        'fileBase': sc.baseEncryptedName,
        'created': DateTime.now().toUtc().toIso8601String(),
        'verifier': base64Encode(verifier),
        'fast': fastMeta,
        'fastSig': base64Encode(fastSig),
        'wrapNonceCounter': 1,
        'entryNonceCounter': 0,
      };
      final metaFile = File('$folderPath/${sc.metaFileName}');
      await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
      await _storeWrappedDerivedKey(folderPath, wrapped);
    });
    sh.zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
  }
  static Future<void> createEmptyDbIsolateEntry(List<dynamic> args) async {
    final SendPort sendPort = args[0];
    final String folderPath = args[1];
    final String password = args[2];
    final int parts = args[3];
    final int memoryKb = args[4];
    final int iterations = args[5];
    final int parallelism = args[6];
    final cryptoService = CryptoService();
    final storageService = StorageService(cryptoService);
    try {
      await storageService.createEmptyDb(
        folderPath: folderPath,
        password: password,
        parts: parts,
        memoryKb: memoryKb,
        iterations: iterations,
        parallelism: parallelism,
      );
      sendPort.send(null);
    } catch (e) {
      sendPort.send(e.toString());
    }
  }
  Future<({String plaintext, SecretKey key})> openDb({
    required String folderPath,
    required String password,
  }) async {
    final metaFile = File('$folderPath/${sc.metaFileName}');
    if (!await metaFile.exists()) {
      throw Exception('Meta file missing. Did you select the correct folder?');
    }
    return _lock.synchronized(() async {
      final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
      final salt = base64Decode(meta['salt'] as String);
      final kdf = meta['kdf'] as String? ?? 'argon2id';
      final iterations = meta['iterations'] as int? ?? 3;
      final memoryKb = meta['memoryKb'] as int? ?? 524288;
      final parallelism = meta['parallelism'] as int? ?? 4;
      SecretKey secretKey;
      final wrappedFromSecure = await _tryReadWrappedFromSecure(folderPath);
      if (wrappedFromSecure != null || await File('$folderPath/${sc.derivedKeyFileName}').exists()) {
        final wrapped = wrappedFromSecure ??
            await File('$folderPath/${sc.derivedKeyFileName}').readAsBytes();
        final fastMeta = meta['fast'] as Map<String, dynamic>?;
        if (fastMeta == null) {
          throw Exception('Missing fast-unlock parameters in metadata.');
        }
        final kdfName = fastMeta['kdf'] as String? ?? 'argon2id';
        if (kdfName != 'argon2id') {
          throw Exception('Unsupported fast KDF: $kdfName');
        }
        final fastSalt = base64Decode(fastMeta['salt'] as String);
        final fIterations = (fastMeta['iterations'] as int?) ?? sc.fastIterations;
        final fMemoryKb = (fastMeta['memoryKb'] as int?) ?? sc.fastMemoryKb;
        final fParallelism = (fastMeta['parallelism'] as int?) ?? sc.fastParallelism;
        final fastKey = await kh.deriveFastKeyArgon2(
          cryptoService,
          password,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
        );
        try {
          final keyBytes = await sh.unwrapKeyWithAesGcm(fastKey, wrapped);
          secretKey = SecretKey(keyBytes);
        } catch (_) {
          throw Exception('Invalid password or corrupted derived key.');
        } finally {
          sh.zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
        }
        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) throw Exception('Missing verifier.');
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await sh.makeVerifier(secretKey);
        final ok = sh.constantTimeEquals(candidate, storedVerifier);
        sh.zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');
        final fastSigB64 = meta['fastSig'] as String?;
        if (fastSigB64 != null) {
          final sig = base64Decode(fastSigB64);
          final expectSig = await sh.signFastParams(secretKey, fastMeta);
          final sigOk = sh.constantTimeEquals(sig, expectSig);
          if (!sigOk) {
            throw Exception('Fast KDF parameters tampered.');
          }
        }
        final partsCount = meta['parts'] as int;
        final bytes = await fh.readAndConcatParts(folderPath, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      } else {
        secretKey = await cryptoService.deriveKeyFromPassword(
          password: password,
          salt: salt,
          kdf: kdf,
          iterations: iterations,
          memoryKb: memoryKb,
          parallelism: parallelism,
        );
        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) {
          throw Exception('Missing verifier.');
        }
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await sh.makeVerifier(secretKey);
        final ok = sh.constantTimeEquals(candidate, storedVerifier);
        sh.zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');
        final fastSalt = sh.secureRandomBytes(sc.fastKdfSaltLen);
        final tuned = await kh.calibrateArgon2(cryptoService, targetMs: sc.fastTargetMs);
        final fIterations = max(tuned.iterations, sc.minIterations);
        final fMemoryKb = max(tuned.memoryKb, sc.minMemoryKb);
        final fParallelism = max(tuned.parallelism, sc.minParallelism);
        final fastKey = await kh.deriveFastKeyArgon2(
          cryptoService,
          password,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
        );
        final wrapNonce = await _nextWrapNonce(folderPath, fastKey);
        final wrapped = await sh.wrapKeyWithAesGcm(
          wrappingKey: fastKey,
          toWrap: await secretKey.extractBytes(),
          nonce: wrapNonce,
        );
        await _storeWrappedDerivedKey(folderPath, wrapped);
        await _updateMetaFastInfo(
          folderPath,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
          masterKey: secretKey,
        );
        sh.zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
        final partsCount = meta['parts'] as int;
        final bytes = await fh.readAndConcatParts(folderPath, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      }
    });
  }
  Future<Uint8List> _nextWrapNonce(String folderPath, SecretKey wrappingKey) async {
    final metaFile = File('$folderPath/${sc.metaFileName}');
    if (!await metaFile.exists()) throw Exception('Meta file missing for nonce management.');
    final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
    final current = (meta['wrapNonceCounter'] as int?) ?? 0;
    final next = current + 1;
    meta['wrapNonceCounter'] = next;
    await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
    return sh.computeWrapNonce(wrappingKey, next);
  }
  Future<void> _storeWrappedDerivedKey(String folderPath, Uint8List wrapped) async {
    final keyId = sh.folderKeyId(folderPath);
    if (await _osSecure.isAvailable()) {
      try {
        await _osSecure.write(keyId, wrapped);
        final f = File('$folderPath/${sc.derivedKeyFileName}');
        if (await f.exists()) await f.delete();
        return;
      } catch (_) {}
    }
    if (!allowDiskWrappedKeyFallback) {
      stderr.writeln(
        'WARNING: OS secure storage unavailable. Skipping disk fallback for wrapped key (opt-in disabled). Fast unlock will be unavailable on this device.',
      );
      return;
    }
    final f = File('$folderPath/${sc.derivedKeyFileName}');
    await f.writeAsBytes(wrapped, flush: true);
    if (!Platform.isWindows) {
      try {
        await Process.run('chmod', ['600', f.path]);
      } catch (_) {}
    }
  }
  Future<Uint8List?> _tryReadWrappedFromSecure(String folderPath) async {
    if (await _osSecure.isAvailable()) {
      try {
        final v = await _osSecure.read(sh.folderKeyId(folderPath));
        if (v != null && v.isNotEmpty) return Uint8List.fromList(v);
      } catch (_) {}
    }
    return null;
  }
  Future<void> _updateMetaFastInfo(
    String folderPath,
    List<int> fastSalt, {
    required int memoryKb,
    required int iterations,
    required int parallelism,
    SecretKey? masterKey,
  }) async {
    final metaFile = File('$folderPath/${sc.metaFileName}');
    if (!await metaFile.exists()) return;
    final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
    final fastMeta = {
      'kdf': 'argon2id',
      'iterations': iterations,
      'memoryKb': memoryKb,
      'parallelism': parallelism,
      'salt': base64Encode(fastSalt),
    };
    meta['fast'] = fastMeta;
    if (masterKey != null) {
      final sig = await sh.signFastParams(masterKey, fastMeta);
      meta['fastSig'] = base64Encode(sig);
    }
    await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
  }
  Future<void> saveDb({
    required String folderPath,
    required SecretKey key,
    required String jsonDb,
  }) async {
    await _lock.synchronized(() async {
      final metaFile = File('$folderPath/${sc.metaFileName}');
      if (!await metaFile.exists()) throw Exception('Meta file missing.');
      final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
      final parts = meta['parts'] as int;
      await fh.backupDb(folderPath, parts);
      final encrypted = await cryptoService.encryptUtf8(key, jsonDb);
      sh.zeroBytes(Uint8List.fromList(utf8.encode(jsonDb)));
      await fh.writePartsAtomic(folderPath, encrypted, parts);
      meta['modified'] = DateTime.now().toUtc().toIso8601String();
      await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
      await fh.cleanupOldBackups(folderPath, parts, keep: 2);
    });
  }
  Future<void> deleteDerivedKey(String folderPath) async {
    try {
      if (await _osSecure.isAvailable()) {
        try {
          await _osSecure.delete(sh.folderKeyId(folderPath));
        } catch (_) {}
      }
      final keyFile = File('$folderPath/${sc.derivedKeyFileName}');
      if (await keyFile.exists()) {
        await keyFile.delete();
      }
    } catch (e) {
      throw Exception('Failed to delete derived key: $e');
    }
  }
  Future<Uint8List> allocateEntryNonce(
    String folderPath,
    SecretKey masterKey, {
    String? entryId,
  }) async {
    final metaFile = File('$folderPath/${sc.metaFileName}');
    if (!await metaFile.exists()) throw Exception('Meta file missing.');
    return await _lock.synchronized(() async {
      final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
      final current = (meta['entryNonceCounter'] as int?) ?? 0;
      final next = current + 1;
      meta['entryNonceCounter'] = next;
      await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
      return sh.computeEntryNonce(masterKey, next, entryId: entryId);
    });
  }
  Future<Map<String, dynamic>> issueEntryChallenge(
    String folderPath,
    SecretKey masterKey, {
    String? entryId,
    int challengeLen = 32,
  }) async {
    final nonce = await allocateEntryNonce(folderPath, masterKey, entryId: entryId);
    final meta = jsonDecode(await File('$folderPath/${sc.metaFileName}').readAsString()) as Map<String, dynamic>;
    final counter = (meta['entryNonceCounter'] as int?) ?? 0;
    final challenge = Uint8List.fromList(sh.secureRandomBytes(challengeLen));
    final accept = await sh.computeEntryAcceptTag(masterKey, counter, challenge, entryId: entryId);
    return {
      'counter': counter,
      'nonce': base64Encode(nonce),
      'challenge': base64Encode(challenge),
      'accept': base64Encode(accept),
      if (entryId != null) 'entryId': entryId,
    };
  }
  Future<bool> verifyEntryAccept(
    SecretKey masterKey, {
    required int counter,
    required Uint8List challenge,
    String? entryId,
    required Uint8List accept,
  }) async {
    final expect = await sh.computeEntryAcceptTag(masterKey, counter, challenge, entryId: entryId);
    final ok = sh.constantTimeEquals(expect, accept);
    sh.zeroBytes(expect);
    return ok;
  }
}
