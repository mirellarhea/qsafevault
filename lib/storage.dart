import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:path_provider/path_provider.dart';
import 'encryption.dart';

class PasswordStorage {
  static Future<String> getAppDir() async {
    final dir = await getApplicationDocumentsDirectory();
    final folder = Directory('${dir.path}/password_manager_data');
    if (!folder.existsSync()) folder.createSync(recursive: true);
    return folder.path;
  }

  static Future<void> saveDatabase(
      List<Uint8List> chunks, Uint8List salt, Uint8List iv) async {
    final path = await getAppDir();
    final meta = {
      'salt': base64Encode(salt),
      'chunks': chunks.length,
      'version': 1,
    };
    File('$path/meta.json').writeAsStringSync(jsonEncode(meta));
    File('$path/iv.bin').writeAsBytesSync(iv);

    for (int i = 0; i < chunks.length; i++) {
      File('$path/chunk_${i + 1}.bin').writeAsBytesSync(chunks[i]);
    }
  }

  static Future<Map<String, dynamic>> loadDatabase() async {
    final path = await getAppDir();
    final metaFile = File('$path/meta.json');
    final ivFile = File('$path/iv.bin');
    if (!metaFile.existsSync() || !ivFile.existsSync()) return {};

    final meta = jsonDecode(metaFile.readAsStringSync());
    final salt = base64Decode(meta['salt']);
    final chunkCount = meta['chunks'] as int;
    final chunks = <Uint8List>[];
    for (int i = 0; i < chunkCount; i++) {
      final chunkFile = File('$path/chunk_${i + 1}.bin');
      if (!chunkFile.existsSync()) return {};
      chunks.add(chunkFile.readAsBytesSync());
    }
    final iv = ivFile.readAsBytesSync();

    return {'chunks': chunks, 'salt': salt, 'iv': iv};
  }
}
