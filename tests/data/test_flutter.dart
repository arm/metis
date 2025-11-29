import 'package:shared_preferences/shared_preferences.dart';

class UserService {
  // Security issue: Storing API key in SharedPreferences without encryption
  Future<void> saveApiKey(String apiKey) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('api_key', apiKey);
  }
  
  // Security issue: Using HTTP instead of HTTPS
  Future<void> fetchData() async {
    final url = 'http://api.example.com/data';
    // Make request...
  }
  
  // Security issue: Hardcoded credentials
  final String username = 'admin';
  final String password = 'password123';
}
