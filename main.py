import base64
import binascii
import string

def hexToBytes(hex_str):
#from challenge 1
  return bytes.fromhex(hex_str)

def base64ToBytes(base64_str):
#from challenge 1
  return base64.b64decode(base64_str)

def bytesToHex(byte_str):
  #from challenge 1
  return byte_str.hex()

def bytesToBase64(hex_str):
  #from challenge 1
  return base64.b64encode(byte_str).decode('utf-8')
  
def fixedXOR(hex_str1, hex_str2):
  #from challenge 2
  byte1 = hexToBytes(hex_str1)
  byte2 = hexToBytes(hex_str2)
  xor_bytes = bytes([b1 ^ b2 for b1, b2 in zip(byte1, byte2)])
  return bytesToHex(xor_bytes)

def SingleByteXOR(ciphertext_hex_str):
  #from challenge 3
    ciphertext_bytes = hexToBytes(ciphertext_hex_str)
    plaintexts = []
    for key in range(256):
        plaintext_bytes = bytes([byte ^ key for byte in ciphertext_bytes])
        plaintext = plaintext_bytes.decode('ascii', errors='ignore')
        score = sum([1 for char in plaintext.lower() if char in string.ascii_lowercase])
        plaintexts.append((score, key, plaintext))
    top_score, top_plaintext, top_key = max(plaintexts, key=lambda x: x[0])
    return top_plaintext, top_key

#testing challenge 1
#hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
#byte_str = hexToBytes(hex_str)
#base64_str = bytesToBase64(byte_str)
#print(base64_str)

#testing challenge 2
#input_hex_str1 = "1c0111001f010100061a024b53535009181c"
#input_hex_str2 = "686974207468652062756c6c277320657965"
#print(fixedXOR(input_hex_str1, input_hex_str2))

#testing challenge 3
ciphertext_hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
plaintext = SingleByteXOR(ciphertext_hex_str)
print(plaintext)





