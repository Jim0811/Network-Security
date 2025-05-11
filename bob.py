import sys 
from typing import List, Dict

def generate_playfair_key_string(key: str) -> str:
    """Generate a 32-character custom alphabet from a key using Playfair rules."""
    DEFAULT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    used_chars = set()
    processed_key = []
    
    # Process the key - remove duplicates but keep both I and J
    for c in key.upper():
        if c in DEFAULT_CHARS and c not in used_chars:
            processed_key.append(c)
            used_chars.add(c)
    
    # Add remaining characters from DEFAULT_CHARS
    for c in DEFAULT_CHARS:
        if c not in used_chars:
            processed_key.append(c)
    
    # Return exactly 32 characters for Base32
    return ''.join(processed_key[:32])

class CustomBase32:
    def __init__(self, alphabet: str):
        if len(alphabet) != 32:
            raise ValueError("Alphabet must be exactly 32 characters")
        self.alphabet = alphabet
        self.char_map = {c: i for i, c in enumerate(alphabet)}
    
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
        
        # Handle remaining bits
        if bits_left > 0:
            index = (buffer << (5 - bits_left)) & 0x1F
            output.append(self.alphabet[index])
        
        return ''.join(output)
    
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
                raise ValueError(f"Invalid character '{c}' in Base32 input")
            
            buffer = (buffer << 5) | self.char_map[c]
            bits_left += 5
            
            if bits_left >= 8:
                bits_left -= 8
                output.append((buffer >> bits_left) & 0xFF)
        
        return bytes(output).decode('utf-8', errors='replace')

def main():
    # Step 1: Get user key and generate Playfair-based Base32 alphabet
    key = input("Enter your key (letters and numbers, case insensitive): ").strip()
    
    try:
        custom_alphabet = generate_playfair_key_string(key)
        print(f"\nGenerated Base32 Alphabet: {custom_alphabet}")
        
        # Step 2: Initialize Base32 encoder/decoder with custom alphabet
        base32 = CustomBase32(custom_alphabet)
        
        # Step 3: Test encoding/decoding
        test_string = "Hello World! 123"
        encoded = base32.encode(test_string)
        decoded = base32.decode(encoded)
        
        print("\nEncoding Test:")
        print(f"Original: {test_string}")
        print(f"Encoded:  {encoded}")
        print(f"Decoded:  {decoded}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()