import sys
from typing import List

def generate_playfair_key_string(key: str) -> str:
    """Generate a 32-character custom alphabet from a key using Playfair rules."""
    DEFAULT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    used_chars = set()
    processed_key = []
    
    for c in key.upper():
        if c in DEFAULT_CHARS and c not in used_chars:
            processed_key.append(c)
            used_chars.add(c)
    
    for c in DEFAULT_CHARS:
        if c not in used_chars:
            processed_key.append(c)
    
    return ''.join(processed_key[:32])

class CustomBase32Encoder:
    def __init__(self, alphabet: str):
        if len(alphabet) != 32:
            raise ValueError("Alphabet must be exactly 32 characters")
        self.alphabet = alphabet
    
    def encode(self, data: str) -> str:
        """Encode data using the custom Base32 alphabet."""
        if not data:
            return ""
        
        buffer = 0
        bits_left = 0
        output = []
        
        for byte in bytearray(data, 'utf-8'):
            buffer = (buffer << 8) | byte
            bits_left += 8
            
            while bits_left >= 5:
                bits_left -= 5
                index = (buffer >> bits_left) & 0x1F
                output.append(self.alphabet[index])
        
        if bits_left > 0:
            index = (buffer << (5 - bits_left)) & 0x1F
            output.append(self.alphabet[index])
        
        return ''.join(output)

def encrypt_data():
    """Main encryption function."""
    key = input("Enter encryption key (letters/numbers): ").strip()
    message = input("Enter message to encrypt: ").strip()
    
    try:
        custom_alphabet = generate_playfair_key_string(key)
        encoder = CustomBase32Encoder(custom_alphabet)
        encrypted = encoder.encode(message)
        
        print("\nEncryption Results:")
        print(f"Custom Alphabet: {custom_alphabet}")
        print(f"Encrypted Message: {encrypted}")
        
    except Exception as e:
        print(f"Encryption Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    encrypt_data()