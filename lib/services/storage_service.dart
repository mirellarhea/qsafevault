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
import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/services.dart';
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

  void _log(String msg) {
  }

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

  Future<String?> pickVaultFileForOpen() async {
    try {
      final res = await FilePicker.platform.pickFiles(
        dialogTitle: 'Open Vault - select .vault file',
        type: FileType.custom,
        allowedExtensions: ['vault'],
        allowMultiple: false,
      );
      final path = res?.files.single.path;
      if (path == null) return null;
      if (!path.toLowerCase().endsWith('.vault')) {
        throw Exception('Please select a .vault file.');
      }
      if (!await File(path).exists()) throw Exception('File not found.');
      return path;
    } catch (e) {
      rethrow;
    }
  }

  bool _isVaultFilePath(String p) => p.toLowerCase().endsWith('.vault');

  String _vaultKeyFilePath(String vaultPath) {
    final dir = File(vaultPath).parent.path;
    final name = vaultPath.split(Platform.pathSeparator).last;
    final base = name.toLowerCase().endsWith('.vault')
        ? name.substring(0, name.length - 6)
        : name;
    return '$dir${Platform.pathSeparator}$base.key';
  }

  static final Uint8List _obfMagic = Uint8List.fromList(utf8.encode('QSV1OBF'));
  List<int> _obfKey(String seed) =>
      crypto.sha256.convert(utf8.encode('QSV_OBF_V1|$seed')).bytes;

  Uint8List _wrapContainerBytes(Uint8List zipBytes, String seed) {
    final key = _obfKey(seed);
    final out = Uint8List(zipBytes.length);
    for (var i = 0; i < zipBytes.length; i++) {
      out[i] = zipBytes[i] ^ key[i % key.length];
    }
    final outAll = BytesBuilder();
    outAll.add(_obfMagic);
    outAll.add(out);
    return Uint8List.fromList(outAll.toBytes());
  }

  Uint8List _unwrapContainerBytes(Uint8List rawBytes, String seed) {
    bool hasMagic = rawBytes.length >= _obfMagic.length;
    if (hasMagic) {
      for (var i = 0; i < _obfMagic.length; i++) {
        if (rawBytes[i] != _obfMagic[i]) {
          hasMagic = false;
          break;
        }
      }
    }
    if (hasMagic) {
      final body = rawBytes.sublist(_obfMagic.length);
      final key = _obfKey(seed);
      final out = Uint8List(body.length);
      for (var i = 0; i < body.length; i++) {
        out[i] = body[i] ^ key[i % key.length];
      }
      return out;
    }
    if (rawBytes.length >= 2 && rawBytes[0] == 0x50 && rawBytes[1] == 0x4B) {
      return rawBytes;
    }
    throw Exception('Invalid vault container format.');
  }

  Future<String> _workingDirForVault(String vaultPath) async {
    final tmp = await getTemporaryDirectory();
    final h = crypto.sha1.convert(utf8.encode(vaultPath)).toString();
    final dir = Directory('${tmp.path}/qsafevault_work/$h');
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir.path;
  }

  Future<void> _unpackVaultToWorkingDir(String vaultPath) async {
    final work = await _workingDirForVault(vaultPath);
    final file = File(vaultPath);
    final raw = await file.readAsBytes();

    final zipped = _unwrapContainerBytes(raw, vaultPath);

    final archive = ZipDecoder().decodeBytes(zipped, verify: true);
    final wdir = Directory(work);
    if (!await wdir.exists()) await wdir.create(recursive: true);
    for (final entry in wdir.listSync(recursive: true)) {
      try {
        if (entry is File) await entry.delete();
      } catch (_) {}
    }
    for (final f in archive) {
      if (f.isFile) {
        final outFile = File('$work/${f.name}');
        await outFile.parent.create(recursive: true);
        await outFile.writeAsBytes(f.content as List<int>, flush: true);
      }
    }
  }

  Future<void> _packWorkingDirToVault(String workingDir, String vaultPath) async {
    final encoder = ZipEncoder();
    final archive = Archive();
    final dir = Directory(workingDir);
    if (!await dir.exists()) throw Exception('Vault working directory missing.');
    for (final entity in dir.listSync(recursive: true)) {
      if (entity is! File) continue;
      final relPath = entity.path.substring(workingDir.length + 1).replaceAll('\\', '/');
      final data = await entity.readAsBytes();
      archive.addFile(ArchiveFile(relPath, data.length, data));
    }
    final zipped = encoder.encode(archive);
    if (zipped == null) throw Exception('Failed to create vault container.');
    final wrapped = _wrapContainerBytes(Uint8List.fromList(zipped), vaultPath);
    final out = File(vaultPath);
    await out.writeAsBytes(wrapped, flush: true);
  }

  Future<String> _resolveDbDirForRead(String path) async {
    if (_isVaultFilePath(path)) {
      await _unpackVaultToWorkingDir(path);
      return _workingDirForVault(path);
    }
    return path;
  }

  Future<String> _resolveDbDirForWrite(String path) async {
    if (_isVaultFilePath(path)) {
      return await _workingDirForVault(path);
    }
    return path;
  }

  String _keyIdSeed(String path) => path;

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

    final isVault = _isVaultFilePath(folderPath);
    final String targetVaultPath = isVault ? folderPath : '';
    String workDir = folderPath;
    if (isVault) {
      workDir = await _workingDirForVault(targetVaultPath);
    } else {
      workDir = await ensureEmptyOrPwdbSubdir(folderPath);
    }

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
      await fh.writePartsAtomic(workDir, encrypted, parts);
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
      final metaFile = File('$workDir/${sc.metaFileName}');
      await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
      final seed = isVault ? targetVaultPath : workDir;
      await _storeWrappedDerivedKey(seed, wrapped);
      if (isVault) {
        await _packWorkingDirToVault(workDir, targetVaultPath);
      }
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
    final RootIsolateToken? token = args.length > 7 ? args[7] as RootIsolateToken? : null;

    if (token != null) {
      BackgroundIsolateBinaryMessenger.ensureInitialized(token);
    }

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
    final isVault = _isVaultFilePath(folderPath);
    final workDir = await _resolveDbDirForRead(folderPath);
    final keySeed = _keyIdSeed(folderPath);

    final metaFile = File('$workDir/${sc.metaFileName}');
    if (!await metaFile.exists()) {
      throw Exception('Meta file missing. Did you select the correct file?');
    }
    return _lock.synchronized(() async {
      final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
      final salt = base64Decode(meta['salt'] as String);
      final kdf = meta['kdf'] as String? ?? 'argon2id';
      final iterations = meta['iterations'] as int? ?? 3;
      final memoryKb = meta['memoryKb'] as int? ?? 524288;
      final parallelism = meta['parallelism'] as int? ?? 4;
      SecretKey secretKey;
      final wrappedFromSecure = await _tryReadWrappedFromSecure(keySeed);

      Uint8List? wrapped;
      if (wrappedFromSecure != null) {
        wrapped = wrappedFromSecure;
        _log('Using derived key from OS secure storage for seed: $keySeed');
      } else if (isVault) {
        final keyFile = File(_vaultKeyFilePath(folderPath));
        if (await keyFile.exists()) {
          wrapped = await keyFile.readAsBytes();
          _log('Using derived key file: ${keyFile.path}');
        } else {
          _log('No derived key file found next to vault. Falling back to slow unlock.');
        }
      } else if (await File('$workDir/${sc.derivedKeyFileName}').exists()) {
        wrapped = await File('$workDir/${sc.derivedKeyFileName}').readAsBytes();
        _log('Using derived key file: $workDir/${sc.derivedKeyFileName}');
      } else {
        _log('No derived key in OS secure storage or disk. Using slow unlock.');
      }

      final bool _usedSecureStorage = wrappedFromSecure != null;
      final bool _usedDiskKey = wrapped != null && !_usedSecureStorage;

      if (wrapped != null) {
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
        final bytes = await fh.readAndConcatParts(workDir, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        if (_usedSecureStorage) {
          _log('Opened vault with fast unlock (secure storage).');
        } else if (_usedDiskKey) {
          _log('Opened vault with fast unlock (disk key file).');
        }
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
        final wrapNonce = await _nextWrapNonce(workDir, fastKey);
        final wrapped = await sh.wrapKeyWithAesGcm(
          wrappingKey: fastKey,
          toWrap: await secretKey.extractBytes(),
          nonce: wrapNonce,
        );
        await _storeWrappedDerivedKey(keySeed, wrapped);
        await _updateMetaFastInfo(
          workDir,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
          masterKey: secretKey,
        );
        sh.zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
        final partsCount = meta['parts'] as int;
        final bytes = await fh.readAndConcatParts(workDir, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        _log('Opened vault with slow unlock (password KDF).');
        return (plaintext: plaintext, key: secretKey);
      }
    });
  }

  Future<Uint8List> _nextWrapNonce(String folderPath, SecretKey wrappingKey) async {
    final workDir = _isVaultFilePath(folderPath) ? await _workingDirForVault(folderPath) : folderPath;
    final metaFile = File('$workDir/${sc.metaFileName}');
    if (!await metaFile.exists()) throw Exception('Meta file missing for nonce management.');
    final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
    final current = (meta['wrapNonceCounter'] as int?) ?? 0;
    final next = current + 1;
    meta['wrapNonceCounter'] = next;
    await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
    return sh.computeWrapNonce(wrappingKey, next);
  }

  Future<void> _storeWrappedDerivedKey(String seedPath, Uint8List wrapped) async {
    final keyId = sh.folderKeyId(seedPath);
    if (await _osSecure.isAvailable()) {
      try {
        await _osSecure.write(keyId, wrapped);
        _log('Derived key stored in OS secure storage for seed: $keyId');
        return;
      } catch (e) {
        _log('Secure storage write failed ($e), considering disk fallback...');
      }
    } else {
      _log('OS secure storage not available on this device.');
    }
    if (!allowDiskWrappedKeyFallback) {
      _log('Disk fallback disabled (allowDiskWrappedKeyFallback=false). No .key file will be written.');
      return;
    }
    if (_isVaultFilePath(seedPath)) {
      final keyPath = _vaultKeyFilePath(seedPath);
      final f = File(keyPath);
      await f.writeAsBytes(wrapped, flush: true);
      if (!Platform.isWindows) {
        try {
          await Process.run('chmod', ['600', f.path]);
        } catch (_) {}
      }
      _log('Derived key written to: $keyPath');
    } else {
      final f = File('$seedPath/${sc.derivedKeyFileName}');
      await f.writeAsBytes(wrapped, flush: true);
      if (!Platform.isWindows) {
        try {
          await Process.run('chmod', ['600', f.path]);
        } catch (_) {}
      }
      _log('Derived key written to: ${f.path}');
    }
  }

  Future<void> deleteDerivedKey(String folderPath) async {
    try {
      final seed = _keyIdSeed(folderPath);
      if (await _osSecure.isAvailable()) {
        try {
          await _osSecure.delete(sh.folderKeyId(seed));
          _log('Deleted derived key from OS secure storage for seed: ${sh.folderKeyId(seed)}');
        } catch (e) {
          _log('Failed to delete from secure storage: $e');
        }
      }
      if (_isVaultFilePath(folderPath)) {
        final keyFile = File(_vaultKeyFilePath(folderPath));
        if (await keyFile.exists()) {
          await keyFile.delete();
          _log('Deleted derived key file: ${keyFile.path}');
        }
      } else {
        final keyFile = File('$folderPath/${sc.derivedKeyFileName}');
        if (await keyFile.exists()) {
          await keyFile.delete();
          _log('Deleted derived key file: ${keyFile.path}');
        }
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
    final workDir = _isVaultFilePath(folderPath) ? await _workingDirForVault(folderPath) : folderPath;
    final metaFile = File('$workDir/${sc.metaFileName}');
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

  Future<void> _updateMetaFastInfo(
    String folderPath,
    List<int> fastSalt, {
    required int memoryKb,
    required int iterations,
    required int parallelism,
    SecretKey? masterKey,
  }) async {
    final workDir = _isVaultFilePath(folderPath) ? await _workingDirForVault(folderPath) : folderPath;
    final metaFile = File('$workDir/${sc.metaFileName}');
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

  Future<Uint8List?> _tryReadWrappedFromSecure(String seedPath) async {
    if (await _osSecure.isAvailable()) {
      try {
        final v = await _osSecure.read(sh.folderKeyId(seedPath));
        if (v != null && v.isNotEmpty) return Uint8List.fromList(v);
      } catch (_) {}
    }
    return null;
  }

  Future<void> saveDb({
    required String folderPath,
    required SecretKey key,
    required String jsonDb,
  }) async {
    await _lock.synchronized(() async {
      final isVault = _isVaultFilePath(folderPath);
      final workDir = await _resolveDbDirForWrite(folderPath);
      final metaFile = File('$workDir/${sc.metaFileName}');
      if (!await metaFile.exists()) throw Exception('Meta file missing.');
      final meta = jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
      final parts = meta['parts'] as int;
      await fh.backupDb(workDir, parts);
      final encrypted = await cryptoService.encryptUtf8(key, jsonDb);
      sh.zeroBytes(Uint8List.fromList(utf8.encode(jsonDb)));
      await fh.writePartsAtomic(workDir, encrypted, parts);
      meta['modified'] = DateTime.now().toUtc().toIso8601String();
      await fh.writeJsonAtomic(metaFile.path, jsonEncode(meta));
      await fh.cleanupOldBackups(workDir, parts, keep: 2);
      if (isVault) {
        await _packWorkingDirToVault(workDir, folderPath);
      }
    });
  }
}
