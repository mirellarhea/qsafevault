import 'dart:io';
import 'dart:typed_data';
import 'storage_constants.dart' as sc;
Future<Uint8List> readAndConcatParts(String folderPath, int parts) async {
  final buffer = <int>[];
  for (var i = 0; i < parts; i++) {
    final file = File('$folderPath/${sc.baseEncryptedName}.part${i + 1}');
    if (!await file.exists()) throw Exception('Missing part: ${file.path}');
    buffer.addAll(await file.readAsBytes());
  }
  return Uint8List.fromList(buffer);
}
Future<void> writePartsAtomic(String folderPath, Uint8List data, int parts) async {
  final n = data.length;
  final partSize = (n / parts).ceil();
  for (var i = 0; i < parts; i++) {
    final start = i * partSize;
    final end = (start + partSize) > n ? n : (start + partSize);
    final slice = data.sublist(start, end);
    final tempFile = File('$folderPath/${sc.baseEncryptedName}.part${i + 1}.tmp');
    await tempFile.writeAsBytes(slice, flush: true);
    final finalFile = File('$folderPath/${sc.baseEncryptedName}.part${i + 1}');
    if (await finalFile.exists()) await finalFile.delete();
    await tempFile.rename(finalFile.path);
  }
}
Future<void> writeJsonAtomic(String path, String json) async {
  final tmpPath = '$path.tmp';
  final tmp = File(tmpPath);
  await tmp.writeAsString(json, flush: true);
  final f = File(path);
  if (await f.exists()) await f.delete();
  await tmp.rename(path);
}
Future<void> backupDb(String folderPath, int parts) async {
  for (var i = 0; i < parts; i++) {
    final file = File('$folderPath/${sc.baseEncryptedName}.part${i + 1}');
    if (await file.exists()) {
      final backupFile =
          File('$folderPath/${sc.baseEncryptedName}.part${i + 1}${sc.backupSuffix}');
      await file.copy(backupFile.path);
    }
  }
}
Future<void> cleanupOldBackups(String folderPath, int parts, {int keep = 2}) async {
  for (var i = 0; i < parts; i++) {
    final base = '$folderPath/${sc.baseEncryptedName}.part${i + 1}';
    final dir = Directory(folderPath);
    final backups = await dir
        .list()
        .where((e) => e is File && e.path.startsWith(base) && e.path.endsWith(sc.backupSuffix))
        .cast<File>()
        .toList();
    backups.sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
    for (var j = keep; j < backups.length; j++) {
      try {
        await backups[j].delete();
      } catch (_) {}
    }
  }
}
