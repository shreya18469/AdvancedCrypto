#hex to base64 conversion
import base64
import binascii


def hex_to_base64(hex_str):
  #hex_bytes = bytes.fromhex(hex_str)
  #base64_bytes = base64.b64encode(hex_bytes)
  #base64_str = base64_bytes.decode('utf-8')
  str_bytes = binascii.unhexlify(hex_str)
  str_base64 = base64.b64encode(str_bytes)
  return str_base64


#test case works!
print(
  hex_to_base64(
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  ))
