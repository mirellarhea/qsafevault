import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;
import 'storage_constants.dart' as sc;
final AesGcm _aesGcm = AesGcm.with256bits();
List<int> secureRandomBytes(int length) =>
    List<int>.generate(length, (_) => Random.secure().nextInt(256));
void zeroBytes(List<int> bytes) {
  for (var i = 0; i < bytes.length; i++) bytes[i] = 0;
}
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]);
  }
  return diff == 0;
}
Future<Uint8List> makeVerifier(SecretKey key) async {
  final keyBytes = Uint8List.fromList(await key.extractBytes());
  try {
    final mac = pc.HMac(pc.SHA3Digest(512), 72);
    mac.init(pc.KeyParameter(keyBytes));
    final data = Uint8List.fromList(utf8.encode(sc.verifierLabel));
    mac.update(data, 0, data.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    return out;
  } finally {
    zeroBytes(keyBytes);
  }
}
String _canonicalFastParamsString(Map<String, dynamic> m) {
  final kdf = (m['kdf'] as String?) ?? 'argon2id';
  final iterations = (m['iterations'] as int?) ?? 0;
  final memoryKb = (m['memoryKb'] as int?) ?? 0;
  final parallelism = (m['parallelism'] as int?) ?? 0;
  final salt = (m['salt'] as String?) ?? '';
  return 'k=$kdf;i=$iterations;m=$memoryKb;p=$parallelism;s=$salt';
}
Future<Uint8List> signFastParams(SecretKey masterKey, Map<String, dynamic> fastMeta) async {
  final keyBytes = Uint8List.fromList(await masterKey.extractBytes());
  try {
    final mac = pc.HMac(pc.SHA3Digest(512), 128);
    mac.init(pc.KeyParameter(keyBytes));
    final canonical = _canonicalFastParamsString(fastMeta);
    final data = Uint8List.fromList(utf8.encode('${sc.fastSigLabel}|$canonical'));
    mac.update(data, 0, data.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    return out;
  } finally {
    zeroBytes(keyBytes);
  }
}
Future<Uint8List> computeWrapNonce(SecretKey wrappingKey, int counter) async {
  final keyBytes = Uint8List.fromList(await wrappingKey.extractBytes());
  try {
    final hmac = crypto.Hmac(crypto.sha256, keyBytes);
    final msg = utf8.encode('${sc.keyWrapLabel}|ctr:$counter');
    final digest = hmac.convert(msg).bytes;
    return Uint8List.fromList(digest.sublist(0, 12));
  } finally {
    zeroBytes(keyBytes);
  }
}
Future<Uint8List> wrapKeyWithAesGcm({
  required SecretKey wrappingKey,
  required List<int> toWrap,
  required Uint8List nonce,
}) async {
  final labelBytes = utf8.encode(sc.keyWrapLabel);
  final msg = Uint8List(labelBytes.length + toWrap.length)
    ..setRange(0, labelBytes.length, labelBytes)
    ..setRange(labelBytes.length, labelBytes.length + toWrap.length, toWrap);
  final secretBox = await _aesGcm.encrypt(
    msg,
    secretKey: wrappingKey,
    nonce: nonce,
  );
  final blob = BytesBuilder();
  blob.add(nonce);
  blob.add(secretBox.cipherText);
  blob.add(secretBox.mac.bytes);
  return Uint8List.fromList(blob.toBytes());
}
Future<Uint8List> unwrapKeyWithAesGcm(SecretKey wrappingKey, List<int> blob) async {
  if (blob.length < 12 + 16) throw Exception('Invalid wrapped blob.');
  final nonce = blob.sublist(0, 12);
  final macLen = 16;
  final macStart = blob.length - macLen;
  final cipherText = blob.sublist(12, macStart);
  final macBytes = blob.sublist(macStart);
  final secretBox = SecretBox(
    Uint8List.fromList(cipherText),
    nonce: Uint8List.fromList(nonce),
    mac: Mac(macBytes),
  );
  final plain = await _aesGcm.decrypt(secretBox, secretKey: wrappingKey);
  final labelBytes = utf8.encode(sc.keyWrapLabel);
  if (plain.length <= labelBytes.length) {
    throw Exception('Wrapped key payload too short.');
  }
  for (var i = 0; i < labelBytes.length; i++) {
    if (plain[i] != labelBytes[i]) {
      throw Exception('Wrapped key label mismatch.');
    }
  }
  final keyBytes = Uint8List.fromList(plain.sublist(labelBytes.length));
  zeroBytes(plain);
  return keyBytes;
}
Future<Uint8List> computeEntryNonce(
  SecretKey masterKey,
  int counter, {
  String? entryId,
}) async {
  final keyBytes = Uint8List.fromList(await masterKey.extractBytes());
  try {
    final hmac = crypto.Hmac(crypto.sha256, keyBytes);
    final sb = StringBuffer('${sc.entryNonceLabel}|nonce|ctr:$counter');
    if (entryId != null) sb.write('|id:$entryId');
    final digest = hmac.convert(utf8.encode(sb.toString())).bytes;
    return Uint8List.fromList(digest.sublist(0, 12));
  } finally {
    zeroBytes(keyBytes);
  }
}
Future<Uint8List> computeEntryAcceptTag(
  SecretKey masterKey,
  int counter,
  Uint8List challenge, {
  String? entryId,
}) async {
  final keyBytes = Uint8List.fromList(await masterKey.extractBytes());
  try {
    final mac = pc.HMac(pc.SHA3Digest(512), 128);
    mac.init(pc.KeyParameter(keyBytes));
    final sb = StringBuffer('${sc.entryNonceLabel}|accept|ctr:$counter');
    if (entryId != null) sb.write('|id:$entryId');
    final prefix = Uint8List.fromList(utf8.encode(sb.toString() + '|chal:'));
    mac.update(prefix, 0, prefix.length);
    mac.update(challenge, 0, challenge.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    zeroBytes(prefix);
    return out;
  } finally {
    zeroBytes(keyBytes);
  }
}
String folderKeyId(String folderPath) {
  final h = crypto.sha256.convert(utf8.encode(folderPath)).bytes;
  final b64 = base64UrlEncode(h);
  return 'qsv_wrapped_$b64';
}
