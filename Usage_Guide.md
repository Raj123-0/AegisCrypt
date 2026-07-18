# Usage Guide 

AegisCrypt offers a clean interactive menu for casual use, and robust CLI arguments for automation.

## Interactive Mode
Simply run the script without arguments. It will loop continuously so you can process multiple messages.
```bash
python aegiscrypt.py
```

## Command-Line Interface (CLI)

### Encoding
Encrypt a message. If no key flag is passed, you will be prompted securely.
```bash
python aegiscrypt.py encode "My highly secret message"
```

**Using a Key File:**
```bash
python aegiscrypt.py encode "Message" --key-file ./secret.key
```

**Using an Environment Variable:**
```bash
export AEGIS_KEY="super_secret_passphrase"
python aegiscrypt.py encode "Message" --key-env AEGIS_KEY
```

### Decoding
Decrypt a base64-encoded ciphertext payload.
```bash
python aegiscrypt.py decode <base64_ciphertext>
```
