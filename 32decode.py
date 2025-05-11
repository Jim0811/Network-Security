import sys
from typing import Dict

def generate_playfair_key_string(key: str) -> str:
    """Generate the same 32-character alphabet used for encryption."""
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

class CustomBase32Decoder:
    def __init__(self, alphabet: str):
        if len(alphabet) != 32:
            raise ValueError("Alphabet must be exactly 32 characters")
        self.char_map = {c: i for i, c in enumerate(alphabet)}
    
    def decode(self, data: str) -> str:
        """Decode data using the custom Base32 alphabet."""
        if not data:
            return ""
        
        buffer = 0
        bits_left = 0
        output = []
        
        for c in data:
            if c not in self.char_map:
                if c == '=':  # Skip padding
                    continue
                raise ValueError(f"Invalid character '{c}' in message")
            
            buffer = (buffer << 5) | self.char_map[c]
            bits_left += 5
            
            if bits_left >= 8:
                bits_left -= 8
                output.append((buffer >> bits_left) & 0xFF)
        
        return bytes(output).decode('utf-8', errors='replace')

def decrypt_data():
    """Main decryption function."""
    key = input("Enter decryption key (letters/numbers): ").strip()
    encrypted = input("Enter message to decrypt: ").strip()
    
    try:
        custom_alphabet = generate_playfair_key_string(key)
        decoder = CustomBase32Decoder(custom_alphabet)
        decrypted = decoder.decode(encrypted)
        
        print("\nDecryption Results:")
        print(f"Custom Alphabet: {custom_alphabet}")
        print(f"Decrypted Message: {decrypted}")
        
    except Exception as e:
        print(f"Decryption Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    decrypt_data()