import base64
import binascii
#Challenge 1- convert Hex to base64
def hexToBytes(hex_str):
  return bytes.fromhex(hex_str)

def base64ToBytes(base64_str):
  return base64.b64decode(base64_str)

def bytesToHex(byte_str):
  return byte_str.hex()

def bytesToBase64(hex_str):
  return base64.b64encode(byte_str).decode('utf-8')

hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
byte_str = hexToBytes(hex_str)
base64_str = bytesToBase64(byte_str)
print(base64_str)





