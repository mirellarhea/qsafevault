import 'dart:convert';

class PasswordEntry {
  String id;
  String site;
  String username;
  String email;
  String password;
  int createdAt;
  int updatedAt;

  PasswordEntry({
    required this.id,
    required this.site,
    required this.username,
    required this.email,
    required this.password,
    required this.createdAt,
    required this.updatedAt,
  });

  factory PasswordEntry.fromJson(Map<String, dynamic> j) {
    return PasswordEntry(
      id: j['id'] as String,
      site: j['site'] as String? ?? '',
      username: j['username'] as String? ?? '',
      email: j['email'] as String? ?? '',
      password: j['password'] as String? ?? '',
      createdAt:
          j['createdAt'] as int? ?? DateTime.now().millisecondsSinceEpoch,
      updatedAt:
          j['updatedAt'] as int? ?? DateTime.now().millisecondsSinceEpoch,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'site': site,
        'username': username,
        'email': email,
        'password': password,
        'createdAt': createdAt,
        'updatedAt': updatedAt,
      };

  static List<PasswordEntry> listFromJson(String jsonStr) {
    final arr = json.decode(jsonStr) as List<dynamic>;
    return arr
        .map((e) => PasswordEntry.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  static String listToJson(List<PasswordEntry> list) {
    final arr = list.map((e) => e.toJson()).toList();
    return json.encode(arr);
  }
}
