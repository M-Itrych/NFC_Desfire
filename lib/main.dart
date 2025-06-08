import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:roger_nfc_services/roger_nfc_services.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NFC DESFire Reader',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const NfcReaderPage(),
    );
  }
}

class NfcReaderPage extends StatefulWidget {
  const NfcReaderPage({super.key});

  @override
  State<NfcReaderPage> createState() => _NfcReaderPageState();
}

class _NfcReaderPageState extends State<NfcReaderPage> {
  final _formKey = GlobalKey<FormState>();
  
  // Controllers for input fields with default values
  final _fbpController = TextEditingController();
  final _lbpController = TextEditingController();
  final _appIdController = TextEditingController();
  final _fileIdController = TextEditingController();
  final _keyNumberController = TextEditingController();
  final _keyController = TextEditingController();
  
  // Output variables
  String _rawOutput = '';
  String _decodedOutput = '';
  String _selectedFormat = 'HEX';
  bool _isReading = false;
  bool _isDecoding = false;
  
  // Services
  late DesfireNfcServices _nfcServices;
  late BinaryConversionServices _conversionServices;
  
  @override
  void initState() {
    super.initState();
    _nfcServices = DesfireNfcServices(debugMode: true);
    _conversionServices = BinaryConversionServices(debugMode: true);
    
    // Set default values
    _fbpController.text = '0';
    _lbpController.text = '8';
    _appIdController.text = '332211';
    _fileIdController.text = '3';
    _keyNumberController.text = '1';
    _keyController.text = '11111111111111111111111111111111';
  }
  
  @override
  void dispose() {
    _fbpController.dispose();
    _lbpController.dispose();
    _appIdController.dispose();
    _fileIdController.dispose();
    _keyNumberController.dispose();
    _keyController.dispose();
    super.dispose();
  }
  
  // Input validators
  String? _validateFBP(String? value) {
    if (value == null || value.isEmpty) {
      return 'FBP jest wymagane';
    }
    if (value.length > 2) {
      return 'FBP może mieć maksymalnie 2 cyfry';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'FBP musi zawierać tylko cyfry';
    }
    final intValue = int.tryParse(value);
    if (intValue == null || intValue > 15) {
      return 'FBP w zakresie 0-15';
    }
    return null;
  }

  String? _validateLBP(String? value) {
    if (value == null || value.isEmpty) {
      return 'LBP jest wymagane';
    }
    if (value.length > 2) {
      return 'LBP może mieć maksymalnie 2 cyfry';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'LBP musi zawierać tylko cyfry hex';
    }
    final intValue = int.tryParse(value);
    if (intValue == null || intValue > 15) {
      return 'LBP w zakresie 0-15';
    }
    return null;
  }
  
  String? _validateAppID(String? value) {
    if (value == null || value.isEmpty) {
      return 'App ID jest wymagane';
    }
    if (value.length != 6) {
      return 'App ID musi mieć dokładnie 6 znaków';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'App ID musi zawierać tylko cyfry';
    }
    return null;
  }
  
  String? _validateFileID(String? value) {
    if (value == null || value.isEmpty) {
      return 'File ID jest wymagane';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'File ID musi zawierać tylko cyfry';
    }
    return null;
  }
  
  String? _validateKeyNumber(String? value) {
    if (value == null || value.isEmpty) {
      return 'Key Number jest wymagane';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Key Number musi zawierać tylko cyfry hex';
    }
    return null;
  }
  
  String? _validateKey(String? value) {
    if (value == null || value.isEmpty) {
      return 'Klucz jest wymagany';
    }
    if (value.length != 32) {
      return 'Klucz musi mieć dokładnie 32 znaki (16 bajtów hex)';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Klucz musi zawierać tylko cyfry hex';
    }
    return null;
  }
  
  // Read data from NFC card
  Future<void> _readNfcData() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    
    setState(() {
      _isReading = true;
      _rawOutput = 'Czytanie danych...';
    });
    
    try {
      final result = await _nfcServices.readDesfire(
        _fbpController.text,
        _lbpController.text,
        _appIdController.text,
        _fileIdController.text,
        _keyNumberController.text,
        _keyController.text,
      );
      
      setState(() {
        _rawOutput = result;
      });
      
    } catch (error) {
      setState(() {
        _rawOutput = 'Błąd: $error';
      });
    } finally {
      setState(() {
        _isReading = false;
      });
    }
  }
  
  // Decode the raw output
  Future<void> _decodeData() async {
    if (_rawOutput.isEmpty || _rawOutput.startsWith('Error:')) {
      setState(() {
        _decodedOutput = 'Brak danych do dekodowania';
      });
      return;
    }

    setState(() {
      _isDecoding = true;
    });
    
    try {
      // Parse FBP and LBP as decimal values (byte positions)
      final fbp = int.tryParse(_fbpController.text) ?? 0;
      final lbp = int.tryParse(_lbpController.text) ?? 0;

      String result;
      if (_selectedFormat == 'BIN') {
        // Convert to binary with byte range
        result = _conversionServices.toFormatedBINString(_rawOutput, fbp, lbp);
      } else if (_selectedFormat == 'ASCII') {
        // Convert to ASCII with byte range
        result = _conversionServices.toASCIIString(_rawOutput, fbp, lbp);
      } else {
        // For HEX, extract the byte range from raw hex data with space formatting
        final totalBytes = _rawOutput.length ~/ 2;
        final maxIndex = totalBytes - 1;
        
        if (fbp > maxIndex || lbp > maxIndex) {
          setState(() {
            _decodedOutput = 'Błąd: FBP ($fbp) lub LBP ($lbp) przekracza dostępne bajty ($maxIndex)';
          });
          return;
        }
        
        String hexResult;
        if (fbp > lbp) {
          // Reverse order for HEX
          final hexPairs = <String>[];
          for (int i = fbp; i >= lbp; i--) {
            final startPos = i * 2;
            hexPairs.add(_rawOutput.substring(startPos, startPos + 2));
          }
          hexResult = hexPairs.join('');
        } else {
          // Normal order for HEX
          final startPos = fbp * 2;
          final endPos = (lbp + 1) * 2;
          hexResult = _rawOutput.substring(startPos, endPos);
        }
        
        // Format with spaces every 2 characters
        final formattedHex = <String>[];
        for (int i = 0; i < hexResult.length; i += 2) {
          formattedHex.add(hexResult.substring(i, i + 2));
        }
        result = formattedHex.join(' ');
      }
      
      setState(() {
        _decodedOutput = result;
      });
      
    } catch (error) {
      setState(() {
        _decodedOutput = 'Błąd dekodowania: $error';
      });
    } finally {
      setState(() {
        _isDecoding = false;
      });
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('NFC DESFire Reader'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Input fields
                Row(
                  children: [
                    Expanded(
                      child: TextFormField(
                        controller: _fbpController,
                        decoration: const InputDecoration(
                          labelText: 'FBP',
                          border: OutlineInputBorder(),
                          helperText: 'Max 2 znaki hex',
                        ),
                        validator: _validateFBP,
                        inputFormatters: [
                          LengthLimitingTextInputFormatter(2),
                          FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: TextFormField(
                        controller: _lbpController,
                        decoration: const InputDecoration(
                          labelText: 'LBP',
                          border: OutlineInputBorder(),
                          helperText: 'Max 2 znaki hex',
                        ),
                        validator: _validateLBP,
                        inputFormatters: [
                          LengthLimitingTextInputFormatter(2),
                          FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                
                TextFormField(
                  controller: _appIdController,
                  decoration: const InputDecoration(
                    labelText: 'App ID',
                    border: OutlineInputBorder(),
                    helperText: 'Dokładnie 6 znaków hex',
                  ),
                  validator: _validateAppID,
                  inputFormatters: [
                    LengthLimitingTextInputFormatter(6),
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                  ],
                ),
                const SizedBox(height: 16),
                
                Row(
                  children: [
                    Expanded(
                      child: TextFormField(
                        controller: _fileIdController,
                        decoration: const InputDecoration(
                          labelText: 'File ID',
                          border: OutlineInputBorder(),
                          helperText: 'Znaki hex',
                        ),
                        validator: _validateFileID,
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: TextFormField(
                        controller: _keyNumberController,
                        decoration: const InputDecoration(
                          labelText: 'Key Number',
                          border: OutlineInputBorder(),
                          helperText: 'Znaki hex',
                        ),
                        validator: _validateKeyNumber,
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                
                TextFormField(
                  controller: _keyController,
                  decoration: const InputDecoration(
                    labelText: 'Key',
                    border: OutlineInputBorder(),
                    helperText: 'Dokładnie 32 znaki hex (16 bajtów)',
                  ),
                  validator: _validateKey,
                  inputFormatters: [
                    LengthLimitingTextInputFormatter(32),
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9A-Fa-f]')),
                  ],
                ),
                const SizedBox(height: 24),
                
                // Read button
                ElevatedButton(
                  onPressed: _isReading ? null : _readNfcData,
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  child: _isReading
                      ? const Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            ),
                            SizedBox(width: 8),
                            Text('Czytanie...'),
                          ],
                        )
                      : const Text('Odczytaj', style: TextStyle(fontSize: 16)),
                ),
                const SizedBox(height: 16),
                
                // Raw output area
                Container(
                  width: double.infinity,
                  height: 120,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.grey),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: SingleChildScrollView(
                    child: Text(
                      _rawOutput.isEmpty ? 'Wynik odczytu pojawi się tutaj...' : _rawOutput,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        color: _rawOutput.isEmpty ? Colors.grey : Colors.black,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                
                // Decode section
                Row(
                  children: [
                    ElevatedButton(
                      onPressed: _isDecoding ? null : _decodeData,
                      child: _isDecoding
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Text('Dekoduj'),
                    ),
                    const SizedBox(width: 16),
                    DropdownButton<String>(
                      value: _selectedFormat,
                      items: const [
                        DropdownMenuItem(value: 'HEX', child: Text('HEX')),
                        DropdownMenuItem(value: 'BIN', child: Text('BIN')),
                        DropdownMenuItem(value: 'ASCII', child: Text('ASCII')),
                      ],
                      onChanged: (String? newValue) {
                        if (newValue != null) {
                          setState(() {
                            _selectedFormat = newValue;
                          });
                        }
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                
                // Decoded output area
                Container(
                  width: double.infinity,
                  height: 120,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.grey),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: SingleChildScrollView(
                    child: Text(
                      _decodedOutput,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
