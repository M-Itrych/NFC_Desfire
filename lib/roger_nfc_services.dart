/// Roger NFC Services Library
/// 
/// A production-ready library for secure NFC DESFire card operations.
/// Provides authentication, data reading, and binary conversion utilities
/// with comprehensive error handling and security measures.
/// 
/// Features:
/// - Secure AES-128 encryption/decryption
/// - DESFire authentication protocol
/// - Data reading with encryption support
/// - Binary conversion utilities
/// - Comprehensive error handling
/// - Debug logging support
/// 
/// Usage:
/// ```dart
/// final nfcService = DesfireNfcServices(debugMode: false);
/// final result = await nfcService.readDesfire(...);
/// ```
library roger_nfc_services;

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/services.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';

// =============================================================================
// EXCEPTIONS AND ERROR TYPES
// =============================================================================

/// Custom exception for NFC operations
class NfcException implements Exception {
  final String message;
  final String? errorCode;
  final dynamic originalError;

  const NfcException(this.message, {this.errorCode, this.originalError});

  @override
  String toString() => 'NfcException: $message${errorCode != null ? ' ($errorCode)' : ''}';
}

/// Custom exception for cryptographic operations
class CryptoException implements Exception {
  final String message;
  final dynamic originalError;

  const CryptoException(this.message, {this.originalError});

  @override
  String toString() => 'CryptoException: $message';
}

/// Custom exception for DESFire protocol errors
class DesfireException implements Exception {
  final String message;
  final String? statusCode;
  final dynamic originalError;

  const DesfireException(this.message, {this.statusCode, this.originalError});

  @override
  String toString() => 'DesfireException: $message${statusCode != null ? ' (Status: $statusCode)' : ''}';
}

// =============================================================================
// PRIVATE CRYPTOGRAPHIC SERVICES
// =============================================================================

/// Private cryptographic services for NFC DESFire operations.
/// 
/// This class handles all cryptographic operations including:
/// - AES-128 encryption/decryption in CBC mode
/// - Secure random number generation
/// - Data rotation for DESFire protocol
/// - AES-CMAC computation
/// 
/// Only accessible within this library for security purposes.
class _CryptoNfcServices {
  static const int _aesKeySize = 16;
  static const int _aesBlockSize = 16;
  static const int _randomSize = 16;

  /// Encrypts data using AES-128 in CBC mode.
  /// 
  /// [data] The data to encrypt (must not be null)
  /// [keyBytes] The encryption key (must be exactly 16 bytes)
  /// [ivBytes] The initialization vector (must be exactly 16 bytes)
  /// 
  /// Returns encrypted data as Uint8List
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if encryption fails
  Uint8List aesEncrypt(Uint8List data, Uint8List keyBytes, {required Uint8List ivBytes}) {
    _validateCryptoInput(data, keyBytes, ivBytes, 'encryption');
    
    try {
      final key = encrypt.Key(keyBytes);
      final iv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final encrypted = encrypter.encryptBytes(data, iv: iv);
      return Uint8List.fromList(encrypted.bytes);
    } catch (e) {
      throw CryptoException('AES encryption failed', originalError: e);
    }
  }

  /// Decrypts data using AES-128 in CBC mode.
  /// 
  /// [data] The encrypted data to decrypt (must not be null)
  /// [keyBytes] The decryption key (must be exactly 16 bytes)
  /// [ivBytes] The initialization vector (must be exactly 16 bytes)
  /// 
  /// Returns decrypted data as Uint8List
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if decryption fails
  Uint8List aesDecrypt(Uint8List data, Uint8List keyBytes, {required Uint8List ivBytes}) {
    _validateCryptoInput(data, keyBytes, ivBytes, 'decryption');
    
    try {
      final key = encrypt.Key(keyBytes);
      final iv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final decrypted = encrypter.decryptBytes(encrypt.Encrypted(data), iv: iv);
      return Uint8List.fromList(decrypted);
    } catch (e) {
      throw CryptoException('AES decryption failed', originalError: e);
    }
  }

  /// Generates a cryptographically secure random byte array.
  /// 
  /// [size] Size of the random data (defaults to 16 bytes for DESFire)
  /// 
  /// Returns a secure random Uint8List
  /// 
  /// Throws [ArgumentError] if size is invalid
  Uint8List generateSecureRandom([int size = _randomSize]) {
    if (size <= 0) {
      throw ArgumentError('Size must be positive, got: $size');
    }
    
    final secureRandom = Random.secure();
    return Uint8List.fromList(List.generate(size, (_) => secureRandom.nextInt(256)));
  }

  /// Rotates a byte array one position to the left.
  /// Used in DESFire authentication protocol.
  /// 
  /// [data] The byte array to rotate (must not be null or empty)
  /// 
  /// Returns rotated byte array
  /// 
  /// Throws [ArgumentError] if data is invalid
  Uint8List rotateLeft(Uint8List data) {
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty');
    }
    
    return Uint8List.fromList([...data.sublist(1), data[0]]);
  }

  /// Computes AES-CMAC with specified output size.
  /// 
  /// [hexKey] Hexadecimal string representation of the key
  /// [hexData] Hexadecimal string representation of the data
  /// [outputBits] Output size in bits (64 or 128)
  /// 
  /// Returns uppercase hexadecimal string of the CMAC
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if computation fails
  static String computeAesCmac(String hexKey, String hexData, int outputBits) {
    if (hexKey.isEmpty || hexData.isEmpty) {
      throw ArgumentError('Key and data cannot be empty');
    }
    if (outputBits != 64 && outputBits != 128) {
      throw ArgumentError('Output bits must be 64 or 128, got: $outputBits');
    }
    if (!_isValidHex(hexKey) || !_isValidHex(hexData)) {
      throw ArgumentError('Key and data must be valid hexadecimal strings');
    }
    
    try {
      final keyBytes = Uint8List.fromList(hex.decode(hexKey));
      final dataBytes = Uint8List.fromList(hex.decode(hexData));
      
      final cmac = CMac(BlockCipher('AES'), outputBits);
      final keyParam = KeyParameter(keyBytes);
      
      cmac.init(keyParam);
      cmac.update(dataBytes, 0, dataBytes.length);
      
      final macBytes = Uint8List(cmac.macSize);
      cmac.doFinal(macBytes, 0);
      
      return hex.encode(macBytes).toUpperCase();
    } catch (e) {
      throw CryptoException('AES-CMAC-$outputBits computation failed', originalError: e);
    }
  }

  /// Validates cryptographic input parameters.
  void _validateCryptoInput(Uint8List data, Uint8List keyBytes, Uint8List ivBytes, String operation) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(keyBytes, 'keyBytes');
    ArgumentError.checkNotNull(ivBytes, 'ivBytes');
    
    if (keyBytes.length != _aesKeySize) {
      throw ArgumentError('Key must be exactly $_aesKeySize bytes for AES-128, got: ${keyBytes.length}');
    }
    if (ivBytes.length != _aesBlockSize) {
      throw ArgumentError('IV must be exactly $_aesBlockSize bytes, got: ${ivBytes.length}');
    }
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty for $operation');
    }
  }

  /// Validates if a string contains only hexadecimal characters.
  static bool _isValidHex(String value) {
    return RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value);
  }
}

// =============================================================================
// DESFIRE NFC SERVICES
// =============================================================================

/// Production-ready DESFire NFC Services for secure card operations.
/// 
/// This service provides:
/// - NFC availability checking
/// - DESFire application selection and authentication
/// - Encrypted data reading from files
/// - Comprehensive error handling and logging
/// 
/// Example usage:
/// ```dart
/// final service = DesfireNfcServices(debugMode: false);
/// 
/// final result = await service.readDesfire(
///   firstBytePosition: '0',
///   lastBytePosition: '15',
///   applicationId: 'F40001',
///   fileId: '01',
///   keyNumber: '00',
///   authKey: '00000000000000000000000000000000',
/// );
/// ```
class DesfireNfcServices {
  static const int _timeout = 10;
  static const String _successStatus = '9100';
  static const String _additionalFrameStatus = '91AF';
  
  final _CryptoNfcServices _crypto = _CryptoNfcServices();
  final bool debugMode;

  /// Creates a new instance of DesfireNfcServices.
  /// 
  /// [debugMode] If true, enables detailed debug logging.
  ///            Should be false in production for security.
  DesfireNfcServices({this.debugMode = false});

  // =============================================================================
  // PUBLIC API METHODS
  // =============================================================================

  /// Checks if NFC is available and enabled on the device.
  /// 
  /// Returns `true` if NFC is available and ready to use, `false` otherwise.
  /// This method handles all platform-specific exceptions gracefully.
  /// 
  /// Never throws exceptions - returns false for any error condition.
  Future<bool> isNfcAvailable() async {
    try {
      final nfcAvailability = await FlutterNfcKit.nfcAvailability;
      
      switch (nfcAvailability) {
        case NFCAvailability.available:
          _debugPrint("✅ NFC is available and enabled");
          return true;
        case NFCAvailability.disabled:
          _debugPrint("⚠️ NFC is available but disabled by user");
          return false;
        case NFCAvailability.not_supported:
          _debugPrint("❌ NFC is not supported on this device");
          return false;
        default:
          _debugPrint("❓ Unknown NFC availability status: $nfcAvailability");
          return false;
      }
    } on PlatformException catch (e) {
      _debugPrint("❌ Platform error checking NFC: ${e.message} (${e.code})");
      return false;
    } catch (e, stackTrace) {
      _debugPrint("❌ Unexpected error checking NFC: $e");
      if (debugMode) _debugPrint("Stack trace: $stackTrace");
      return false;
    }
  }

  /// Main entry point for DESFire card processing with encrypted connection.
  /// 
  /// Performs the complete DESFire read operation:
  /// 1. Validates all input parameters
  /// 2. Polls for NFC card
  /// 3. Selects the application
  /// 4. Authenticates with the card
  /// 5. Reads and decrypts file data
  /// 
  /// Parameters:
  /// - [firstBytePosition] First byte position as string (0-based)
  /// - [lastBytePosition] Last byte position as string (0-based)
  /// - [applicationId] Application ID as hex string (6 characters)
  /// - [fileId] File ID as hex string
  /// - [keyNumber] Key number as hex string
  /// - [authKey] Authentication key as hex string (32 characters)
  /// 
  /// Returns the processed data as hex string or error message.
  /// 
  /// Note: This method catches all exceptions and returns error messages
  /// instead of throwing, making it safe for UI integration.
  Future<String> readDesfire(
    String firstBytePosition,
    String lastBytePosition,
    String applicationId,
    String fileId,
    String keyNumber,
    String authKey,
  ) async {
    try {
      _validateReadDesfireParameters(
        firstBytePosition, lastBytePosition, applicationId,
        fileId, keyNumber, authKey,
      );

      if (!await isNfcAvailable()) {
        throw const NfcException("NFC is not available on this device");
      }

      final result = await _performDesfireRead(
        firstBytePosition, lastBytePosition, applicationId,
        fileId, keyNumber, authKey,
      );

      _debugPrint("✅ DESFire read operation completed successfully");
      return result;
      
    } on ArgumentError catch (e) {
      final error = "Invalid parameter: $e";
      _debugPrint("❌ $error");
      return "Error: $error";
    } on TimeoutException catch (e) {
      final error = "Operation timed out: $e";
      _debugPrint("❌ $error");
      return "Error: $error";
    } on NfcException catch (e) {
      _debugPrint("❌ NFC error: $e");
      return "Error: $e";
    } on DesfireException catch (e) {
      _debugPrint("❌ DESFire error: $e");
      return "Error: $e";
    } on CryptoException catch (e) {
      _debugPrint("❌ Crypto error: $e");
      return "Error: $e";
    } catch (e, stackTrace) {
      _debugPrint("❌ Unexpected error: $e");
      if (debugMode) _debugPrint("Stack trace: $stackTrace");
      return "Error: Unexpected error occurred - $e";
    } finally {
      await _finishNfcSession();
    }
  }

  // =============================================================================
  // PRIVATE IMPLEMENTATION METHODS
  // =============================================================================

  /// Performs the complete DESFire read operation.
  Future<String> _performDesfireRead(
    String firstBytePosition,
    String lastBytePosition,
    String applicationId,
    String fileId,
    String keyNumber,
    String authKey,
  ) async {
    // Poll for NFC card
    final nfcTag = await _pollForCard();
    
    // Select application
    await _selectApplication(applicationId);
    
    // Get file settings
    final fileSettings = await _getFileSettings(fileId);
    
    // Authenticate and read data
    final sessionKey = await _authenticateWithApplication(authKey, keyNumber);
    
    return await _readEncryptedData(
      firstBytePosition, lastBytePosition, fileId,
      sessionKey, fileSettings,
    );
  }

  /// Polls for an NFC card with timeout.
  Future<NFCTag> _pollForCard() async {
    _debugPrint("🔍 Starting NFC polling...");
    
    final nfcTag = await FlutterNfcKit.poll(
      timeout: const Duration(seconds: _timeout),
      iosMultipleTagMessage: "Multiple tags found!",
      iosAlertMessage: "Scan your DESFire card",
    ).timeout(const Duration(seconds: _timeout));
    
    _debugPrint("📱 Tag detected: ${nfcTag.type}");
    
    if (nfcTag.type != NFCTagType.iso7816) {
      throw NfcException(
        "Unsupported tag type: ${nfcTag.type}. Expected ISO7816 (DESFire)",
      );
    }
    
    _debugPrint("📋 Tag standard: ${nfcTag.standard}");
    _debugPrint("🆔 Tag ID: ${nfcTag.id}");
    
    return nfcTag;
  }

  /// Selects the DESFire application.
  Future<void> _selectApplication(String applicationId) async {
    final selectCommand = "905A000003${applicationId}00";
    _debugPrint("📂 Selecting application: $selectCommand");
    
    final response = await _transceiveCommand(selectCommand);
    _validateCardResponse(response, 4, _successStatus);
    
    _debugPrint("✅ Application selected successfully");
  }

  /// Authenticates with the selected DESFire application using AES.
  Future<Uint8List> _authenticateWithApplication(String authKey, String keyNumber) async {
    _debugPrint("🔐 Starting AES authentication...");
    
    final keyBytes = Uint8List.fromList(hex.decode(authKey));
    
    // Step 1: Send authentication command
    final authCommand = "90AA0000010${keyNumber}00";
    _debugPrint("📤 Auth command: $authCommand");
    
    final authResponse = await _transceiveCommand(authCommand);
    _validateCardResponse(authResponse, 36, _additionalFrameStatus);
    
    // Step 2: Decrypt RandomB
    final encryptedRandomB = authResponse.substring(0, 32);
    final encryptedRandomBBytes = Uint8List.fromList(hex.decode(encryptedRandomB));
    final decryptedRandomB = _crypto.aesDecrypt(
      encryptedRandomBBytes,
      keyBytes,
      ivBytes: Uint8List(16),
    );
    
    _debugPrint("🎲 Decrypted RandomB: ${hex.encode(decryptedRandomB)}");
    
    // Step 3: Generate RandomA and create response
    final randomA = _crypto.generateSecureRandom();
    final rotatedRandomB = _crypto.rotateLeft(decryptedRandomB);
    final randomARandomB = Uint8List.fromList(randomA + rotatedRandomB);
    
    final encryptedResponse = _crypto.aesEncrypt(
      randomARandomB,
      keyBytes,
      ivBytes: encryptedRandomBBytes,
    );
    
    // Step 4: Send encrypted response
    final responseCommand = "90AF000020${hex.encode(encryptedResponse).toUpperCase()}00";
    final cardResponse = await _transceiveCommand(responseCommand);
    _validateCardResponse(cardResponse, 36, _successStatus);
    
    // Step 5: Verify card's response
    final encryptedRandomAPrime = cardResponse.substring(0, 32);
    final encryptedRandomAPrimeBytes = Uint8List.fromList(hex.decode(encryptedRandomAPrime));
    
    final rotatedRandomA = _crypto.aesDecrypt(
      encryptedRandomAPrimeBytes,
      keyBytes,
      ivBytes: encryptedResponse.sublist(16, 32),
    );
    
    final expectedRotatedRandomA = _crypto.rotateLeft(randomA);
    
    if (!_verifyRotatedRandomA(rotatedRandomA, expectedRotatedRandomA)) {
      throw const DesfireException("Authentication failed: RandomA verification mismatch");
    }
    
    // Step 6: Generate session key
    final sessionKey = _generateSessionKey(randomA, decryptedRandomB);
    _debugPrint("🔑 Session key generated successfully");
    
    return sessionKey;
  }

  /// Gets file settings for the specified file.
  Future<Map<String, String>> _getFileSettings(String fileId) async {
    final fileIdInt = int.parse(fileId, radix: 16);
    final fileIdHex = fileIdInt.toRadixString(16).padLeft(2, '0');
    
    final command = "90F5000001${fileIdHex}00";
    _debugPrint("📄 Getting file settings: $command");
    
    final response = await _transceiveCommand(command);
    _validateCardResponse(response, 14, _successStatus);
    
    final responseData = response.substring(0, response.length - 4);
    
    if (responseData.length < 8) {
      throw DesfireException("Insufficient file settings data: $responseData");
    }
    
    final settings = {
      'fileType': responseData.substring(0, 2),
      'communicationType': responseData.substring(2, 4),
      'accessRights': responseData.substring(4, 8),
      'rawResponse': response,
    };
    
    _debugPrint("📋 File settings: $settings");
    return settings;
  }

  /// Reads encrypted data from the file.
  Future<String> _readEncryptedData(
    String firstBytePosition,
    String lastBytePosition,
    String fileId,
    Uint8List sessionKey,
    Map<String, String> fileSettings,
  ) async {
    final offset = int.parse(firstBytePosition);
    final length = int.parse(lastBytePosition);
    final fileIdInt = int.parse(fileId, radix: 16);
    
    final (actualOffset, actualLength, shouldReverse) = _calculateReadParameters(offset, length);
    
    final offsetHex = _to3ByteLEHex(0);
    final lengthHex = _to3ByteLEHex(16);
    final fileIdHex = fileIdInt.toRadixString(16).padLeft(2, '0');
    
    final readCommand = "90BD000007${fileIdHex}${offsetHex}${lengthHex}00";
    _debugPrint("📖 Reading data: $readCommand");
    
    final readResponse = await _transceiveCommand(readCommand);
    
    if (readResponse.length < 6) {
      throw DesfireException("FBP and LBP must be in range 0-16: $readResponse");
    }
    
    final responseData = Uint8List.fromList(
      hex.decode(readResponse.substring(0, readResponse.length - 4))
    );
    
    Uint8List decryptedData;
    if (fileSettings['communicationType'] == '03') {
      decryptedData = await _decryptFileData(
        responseData, sessionKey, fileIdHex, offsetHex, lengthHex,
      );
    } else {
      decryptedData = responseData;
    }
    
    final hexString = hex.encode(decryptedData).substring(0, 32).toUpperCase();
    
    return shouldReverse ? _reverseHexBytes(hexString) : hexString;
  }

  /// Decrypts file data using session key and CMAC-derived IV.
  Future<Uint8List> _decryptFileData(
    Uint8List responseData,
    Uint8List sessionKey,
    String fileIdHex,
    String offsetHex,
    String lengthHex,
  ) async {
    final sessionKeyHex = hex.encode(sessionKey);
    final commandData = "BD${fileIdHex}${offsetHex}${lengthHex}";
    
    final iv = _CryptoNfcServices.computeAesCmac(sessionKeyHex, commandData, 128);
    final ivBytes = Uint8List.fromList(hex.decode(iv));
    
    _debugPrint("🔓 Decrypting with IV: $iv");
    
    return _crypto.aesDecrypt(responseData, sessionKey, ivBytes: ivBytes);
  }

  // =============================================================================
  // UTILITY METHODS
  // =============================================================================

  /// Safely executes an NFC transceive command with timeout.
  Future<String> _transceiveCommand(String command) async {
    try {
      return await FlutterNfcKit.transceive(command)
          .timeout(const Duration(seconds: 5));
    } on TimeoutException {
      throw const NfcException("Card communication timeout");
    } catch (e) {
      throw NfcException("Card communication failed", originalError: e);
    }
  }

  /// Validates input parameters for the main read operation.
  void _validateReadDesfireParameters(
    String firstBytePosition,
    String lastBytePosition,
    String applicationId,
    String fileId,
    String keyNumber,
    String authKey,
  ) {
    final params = {
      'firstBytePosition': firstBytePosition,
      'lastBytePosition': lastBytePosition,
      'applicationId': applicationId,
      'fileId': fileId,
      'keyNumber': keyNumber,
      'authKey': authKey,
    };
    
    for (final entry in params.entries) {
      if (entry.value.isEmpty) {
        throw ArgumentError("${entry.key} cannot be empty");
      }
    }
    
    _validateHexString(applicationId, 'Application ID', expectedLength: 6);
    _validateHexString(authKey, 'Authentication key', expectedLength: 32);
    _validateHexString(fileId, 'File ID');
    _validateHexString(keyNumber, 'Key number');
  }

  /// Validates a hexadecimal string parameter.
  void _validateHexString(String hexString, String parameterName, {int? expectedLength}) {
    if (!_CryptoNfcServices._isValidHex(hexString)) {
      throw ArgumentError('$parameterName must contain only hexadecimal characters');
    }
    
    if (expectedLength != null && hexString.length != expectedLength) {
      throw ArgumentError(
        '$parameterName must be exactly $expectedLength characters long, got: ${hexString.length}',
      );
    }
  }

  /// Validates card response format and status.
  void _validateCardResponse(String response, int expectedMinLength, String expectedStatus) {
    if (response.length < expectedMinLength) {
      throw DesfireException(
        "Card response too short: expected at least $expectedMinLength characters, got ${response.length}",
      );
    }
    
    if (!response.toUpperCase().endsWith(expectedStatus.toUpperCase())) {
      final actualStatus = response.length >= 4 ? response.substring(response.length - 4) : response;
      final errorMessage = _getDesfireErrorMessage(actualStatus);
      throw DesfireException(
        "Card operation failed: $errorMessage",
        statusCode: actualStatus,
      );
    }
  }

  /// Verifies rotated RandomA using constant-time comparison.
  bool _verifyRotatedRandomA(Uint8List received, Uint8List expected) {
    if (received.length != expected.length) {
      _debugPrint('❌ RandomA length mismatch: ${received.length} vs ${expected.length}');
      return false;
    }
    
    int result = 0;
    for (int i = 0; i < received.length; i++) {
      result |= received[i] ^ expected[i];
    }
    
    final isValid = result == 0;
    _debugPrint(isValid ? '✅ RandomA verified' : '❌ RandomA verification failed');
    
    return isValid;
  }

  /// Generates session key from RandomA and RandomB.
  Uint8List _generateSessionKey(Uint8List randomA, Uint8List randomB) {
    final sessionKey = Uint8List(16);
    sessionKey.setRange(0, 4, randomA, 0);
    sessionKey.setRange(4, 8, randomB, 0);
    sessionKey.setRange(8, 12, randomA, 12);
    sessionKey.setRange(12, 16, randomB, 12);
    return sessionKey;
  }

  /// Calculates read parameters and determines if byte reversal is needed.
  (int offset, int length, bool shouldReverse) _calculateReadParameters(int fbp, int lbp) {
    if (fbp > lbp) {
      return (lbp, fbp, true);
    } else {
      return (fbp, lbp, false);
    }
  }

  /// Converts integer to 3-byte little-endian hex string.
  String _to3ByteLEHex(int value) {
    if (value < 0 || value > 0xFFFFFF) {
      throw ArgumentError('Value must be between 0 and 0xFFFFFF, got: $value');
    }
    
    return [
      (value & 0xFF).toRadixString(16).padLeft(2, '0'),
      ((value >> 8) & 0xFF).toRadixString(16).padLeft(2, '0'),
      ((value >> 16) & 0xFF).toRadixString(16).padLeft(2, '0'),
    ].join();
  }

  /// Reverses byte order in hex string.
  String _reverseHexBytes(String hexString) {
    final hexPairs = <String>[];
    for (int i = 0; i < hexString.length; i += 2) {
      hexPairs.add(hexString.substring(i, i + 2));
    }
    return hexPairs.reversed.join('');
  }

  /// Gets human-readable error message for DESFire status codes.
  String _getDesfireErrorMessage(String statusCode) {
    if (statusCode.length != 4) return "Invalid status code format";
    
    final errorCode = statusCode.substring(2).toUpperCase();
    
    const errorMessages = {
      "00": "Success",
      "0C": "No change",
      "0E": "Out of EEPROM",
      "1C": "Illegal command",
      "1E": "Integrity error",
      "40": "No such key",
      "6E": "Error (ISO)",
      "7E": "Length error",
      "97": "Crypto error",
      "9D": "Permission denied",
      "9E": "Parameter error",
      "A0": "Application not found",
      "AE": "Authentication error",
      "AF": "Additional frame",
      "BE": "Boundary error",
      "C1": "Card integrity error",
      "CA": "Command aborted",
      "CD": "Card disabled",
      "CE": "Count error",
      "DE": "Duplicate error",
      "EE": "EEPROM error",
      "F0": "File not found",
      "F1": "File integrity error",
    };
    
    return errorMessages[errorCode] ?? "Unknown error code: $errorCode";
  }

  /// Safely finishes the NFC session.
  Future<void> _finishNfcSession() async {
    try {
      await FlutterNfcKit.finish(iosAlertMessage: "Scan completed");
      _debugPrint("📱 NFC session finished");
    } catch (e) {
      _debugPrint("⚠️ Error finishing NFC session: $e");
    }
  }

  /// Prints debug messages only when debug mode is enabled.
  void _debugPrint(String message) {
    if (debugMode) {
      print('[${DateTime.now().toIso8601String()}] DESFire: $message');
    }
  }
}

// =============================================================================
// BINARY CONVERSION SERVICES
// =============================================================================

/// Production-ready binary conversion utilities for data processing.
/// 
/// Provides various conversion methods for binary data formats with
/// comprehensive input validation and error handling.
/// 
/// Features:
/// - Hex to binary conversion with formatting
/// - Binary to hex conversion
/// - Hex to ASCII conversion
/// - Byte range extraction with optional reversal
/// - Input validation and sanitization
class BinaryConversionServices {
  final bool debugMode;

  /// Creates a new instance of BinaryConversionServices.
  /// 
  /// [debugMode] If true, enables debug logging.
  BinaryConversionServices({this.debugMode = false});

  /// Converts hex string to formatted binary string with byte range extraction.
  /// 
  /// [hexString] The hex string to convert (must be valid hex)
  /// [fbp] First byte position (0-based index)
  /// [lbp] Last byte position (0-based index)
  /// 
  /// Returns binary string for the specified byte range with line breaks every 8 bits.
  /// If FBP > LBP, bytes are processed in reverse order.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toFormatedBINString(String hexString, int fbp, int lbp) {
    _validateHexString(hexString);
    _validateBytePositions(hexString, fbp, lbp);
    
    final binaryLines = <String>[];
    final (startPos, endPos, isReversed) = _calculateRange(fbp, lbp);
    
    if (isReversed) {
      for (int i = startPos; i >= endPos; i--) {
        binaryLines.add(_hexByteAt(hexString, i).toRadixString(2).padLeft(8, '0'));
      }
    } else {
      for (int i = startPos; i <= endPos; i++) {
        binaryLines.add(_hexByteAt(hexString, i).toRadixString(2).padLeft(8, '0'));
      }
    }
    
    return binaryLines.join('\n');
  }

  /// Converts binary string to hex string with byte range extraction.
  /// 
  /// [binaryString] The binary string to convert (must contain only 0s and 1s)
  /// [fbp] First byte position (0-based index)
  /// [lbp] Last byte position (0-based index)
  /// 
  /// Returns hex string for the specified byte range.
  /// If FBP > LBP, bytes are processed in reverse order.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toHexFromBINString(String binaryString, int fbp, int lbp) {
    _validateBinaryString(binaryString);
    _validateBinaryBytePositions(binaryString, fbp, lbp);
    
    final hexString = StringBuffer();
    final (startPos, endPos, isReversed) = _calculateRange(fbp, lbp);
    
    if (isReversed) {
      for (int i = startPos; i >= endPos; i--) {
        final byteStart = i * 8;
        final byte = binaryString.substring(byteStart, byteStart + 8);
        final hexByte = int.parse(byte, radix: 2).toRadixString(16).padLeft(2, '0');
        hexString.write(hexByte);
      }
    } else {
      for (int i = startPos; i <= endPos; i++) {
        final byteStart = i * 8;
        final byte = binaryString.substring(byteStart, byteStart + 8);
        final hexByte = int.parse(byte, radix: 2).toRadixString(16).padLeft(2, '0');
        hexString.write(hexByte);
      }
    }
    
    return hexString.toString().toUpperCase();
  }

  /// Converts hex string to ASCII string with byte range extraction.
  /// 
  /// [hexString] The hex string to convert (must be valid hex)
  /// [fbp] First byte position (0-based index)
  /// [lbp] Last byte position (0-based index)
  /// 
  /// Returns ASCII string for the specified byte range.
  /// If FBP > LBP, bytes are processed in reverse order.
  /// Non-printable characters (outside 32-126 range) are replaced with '.'.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toASCIIString(String hexString, int fbp, int lbp) {
    _validateHexString(hexString);
    _validateBytePositions(hexString, fbp, lbp);
    
    final asciiString = StringBuffer();
    final (startPos, endPos, isReversed) = _calculateRange(fbp, lbp);
    
    if (isReversed) {
      for (int i = startPos; i >= endPos; i--) {
        final byte = _hexByteAt(hexString, i);
        asciiString.write(_byteToAsciiChar(byte));
      }
    } else {
      for (int i = startPos; i <= endPos; i++) {
        final byte = _hexByteAt(hexString, i);
        asciiString.write(_byteToAsciiChar(byte));
      }
    }
    
    return asciiString.toString();
  }

  // =============================================================================
  // PRIVATE UTILITY METHODS
  // =============================================================================

  /// Validates hex string format and content.
  void _validateHexString(String hexString) {
    ArgumentError.checkNotNull(hexString, 'hexString');
    
    if (hexString.isEmpty) {
      throw ArgumentError('Hex string cannot be empty');
    }
    if (hexString.length % 2 != 0) {
      throw ArgumentError('Hex string length must be even, got: ${hexString.length}');
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(hexString)) {
      throw ArgumentError('Hex string must contain only hexadecimal characters');
    }
  }

  /// Validates binary string format and content.
  void _validateBinaryString(String binaryString) {
    ArgumentError.checkNotNull(binaryString, 'binaryString');
    
    if (binaryString.isEmpty) {
      throw ArgumentError('Binary string cannot be empty');
    }
    if (binaryString.length % 8 != 0) {
      throw ArgumentError('Binary string length must be multiple of 8, got: ${binaryString.length}');
    }
    if (!RegExp(r'^[01]+$').hasMatch(binaryString)) {
      throw ArgumentError('Binary string must contain only 0s and 1s');
    }
  }

  /// Validates byte positions for hex string operations.
  void _validateBytePositions(String hexString, int fbp, int lbp) {
    if (fbp < 0 || lbp < 0) {
      throw ArgumentError('Byte positions must be non-negative, got fbp: $fbp, lbp: $lbp');
    }
    
    final totalBytes = hexString.length ~/ 2;
    final maxIndex = totalBytes - 1;
    
    if (fbp > maxIndex || lbp > maxIndex) {
      throw ArgumentError(
        'Byte positions exceed available bytes (max: $maxIndex), got fbp: $fbp, lbp: $lbp',
      );
    }
  }

  /// Validates byte positions for binary string operations.
  void _validateBinaryBytePositions(String binaryString, int fbp, int lbp) {
    if (fbp < 0 || lbp < 0) {
      throw ArgumentError('Byte positions must be non-negative, got fbp: $fbp, lbp: $lbp');
    }
    
    final totalBytes = binaryString.length ~/ 8;
    final maxIndex = totalBytes - 1;
    
    if (fbp > maxIndex || lbp > maxIndex) {
      throw ArgumentError(
        'Byte positions exceed available bytes (max: $maxIndex), got fbp: $fbp, lbp: $lbp',
      );
    }
  }

  /// Calculates processing range and determines if reversal is needed.
  (int startPos, int endPos, bool isReversed) _calculateRange(int fbp, int lbp) {
    if (fbp > lbp) {
      return (fbp, lbp, true);
    } else {
      return (fbp, lbp, false);
    }
  }

  /// Extracts a byte value from hex string at specified position.
  int _hexByteAt(String hexString, int byteIndex) {
    final byteHex = hexString.substring(byteIndex * 2, (byteIndex * 2) + 2);
    return int.parse(byteHex, radix: 16);
  }

  /// Converts byte value to ASCII character or '.' for non-printable.
  String _byteToAsciiChar(int byte) {
    return (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
  }

  /// Prints debug messages only when debug mode is enabled.
  void _debugPrint(String message) {
    if (debugMode) {
      print('[${DateTime.now().toIso8601String()}] BinaryConversion: $message');
    }
  }
}