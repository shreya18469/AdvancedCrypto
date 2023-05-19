#Shreya Suresh 
#Crypto Challenge- 5/19/23
import base64
from subprocess import check_output as run
from base64 import b64decode
#import re
#from collections import Counter

def hexToBytes(hex_str):
  #from challenge 1
  #convert hex to bytes
  return bytes.fromhex(hex_str)

def base64ToBytes(base64_str):
  #from challenge 1
  #convert base64 to bytes
  return base64.b64decode(base64_str)

def bytesToHex(byte_str):
  #from challenge 1
  #convert bytes to hex
  return byte_str.hex()

def bytesToBase64(hex_str):
  #from challenge 1
  #convert bytes to base64
  return base64.b64encode(hex_str).decode('utf-8')

def fixedXOR(hex_str1, hex_str2):
  #from challenge 2
  #takes two equal-length buffers and produces their XOR combination
  byte1 = hexToBytes(hex_str1)
  byte2 = hexToBytes(hex_str2)
  xor_bytes = bytes([b1 ^ b2 for b1, b2 in zip(byte1, byte2)])
  return bytesToHex(xor_bytes)

def bytesToAscii(bytes):
  #from challenge 3
  #convert bytes to Ascii
  return bytes.decode('utf-8', 'ignore')

def SingleByteXOR(ciphertext, key):
  #from challenge 3
  plaintext = b''
  for byte in ciphertext:
    plaintext += bytes([byte ^ key])
  return plaintext

def detectSingleXOR(ciphertext, num_top_scores=1):
  #from challenge 3
  #method for scoring a piece of plaintext based on lowercase letters
  scores = []
  for key in range(256):
    plaintext = bytesToAscii(SingleByteXOR(ciphertext, key))
    score = sum(1 for c in plaintext if c.islower())
    scores.append({'key': key, 'plaintext': plaintext, 'score': score})
  scores.sort(key=lambda x: x['score'], reverse=True)
  top_scores = scores[:num_top_scores]
  return top_scores

def detectSingleXOR_file(filename):
  #from challenge 4
  #reads the file line by line, detects single byte XOR cipher that has been used to encrypt each line
  top_score = 0
  top_key = None
  top_plaintext = None

  with open(filename, 'r') as f:
    for line in f:
      ciphertext = hexToBytes(line.strip())
      scores = detectSingleXOR(ciphertext)
      #if score of detected cipher is higher than current highest score, update highest key, score, and plaintext
      if scores[0]['score'] > top_score:
        top_score = scores[0]['score']
        top_key = scores[0]['key']
        top_plaintext = scores[0]['plaintext']

  return {'key': top_key, 'plaintext': top_plaintext, 'score': top_score}

def repeatingXOR(plaintext, key):
  #from challenge 5
  #returns the ciphertext resulting from applying the repeating key XOR cipher to plaintext
  key_bytes = key.encode()
  key_length = len(key_bytes)
  ciphertext = b''
  #Loop over each byte in the plaintext
  for i, byte in enumerate(plaintext):
    #Get the corresponding byte of the key
    key_byte = key_bytes[i % key_length]
    #XOR the plaintext byte with the key byte
    ciphertext += bytes([byte ^ key_byte])
  return ciphertext

#Challenge 6 below
def key_sizes():
  #Generate a list of possible key sizes from 2-40
  start = 2
  end = 40
  return list(range(start, end + 1))

def hammingDist(a, b):
  #Compute hamming distance between two inputs
  xor_bytes = [a[i] ^ b[i] for i, x in enumerate(a)]
  binary_bytes = [bin(i)[2:] for i in xor_bytes]
  binary_string = ''.join(binary_bytes)
  binary = list(map(int, list(binary_string)))
  count = sum(binary)
  return count

def splitChunks(iterable, chunk_size):
  #Splits into chunks
  chunks = [
    iterable[i:i + chunk_size] for i in range(0, len(iterable), chunk_size)
    if i < len(iterable) - chunk_size
  ]
  return chunks

def normHammingDist(text, key_size):
  #Compute normalized hamming distance for two strings given key size
  bytelist = b64decode(text)
  # break cipher text into chunks
  chunks = splitChunks(bytelist, key_size)
  # select two leading blocks
  blocks = [bytelist[0:key_size], bytelist[key_size:key_size * 2]]
  hamming_distances = [[hammingDist(block, chunk) for chunk in chunks]
                       for block in blocks][0]
  #average all Hamming distances
  mean = sum(hamming_distances) / len(hamming_distances)
  #normalize by key size
  normalized = mean / key_size
  return normalized

def smallest(values):
  #Find key sizes corresponding to the smallest hamming distances
  sorted_values = sorted(values, key=lambda x: x.get('distance'))
  return sorted_values[0].get('key_size')

def find_key_size(text):
  #find the key size that is most likely
  # compute hamming distance
  normalized_hamming_distances = [{
    'key_size':
    key_size,
    'distance':
    normHammingDist(text, key_size)
  } for key_size in key_sizes()]
  # choose the smallest key size
  keys = smallest(normalized_hamming_distances)
  return keys

def transpose(text, size):
  #Transpose(exchange rows and columns) input text
  bytelist = b64decode(text)
  chunks = splitChunks(bytelist, size)
  transposed = list(zip(*chunks))
  return transposed

def detectKey(strings):
  #guess a likely key
  common = list('etaoin shrdlu')
  counts = [
    sum([string.count(character) for character in common])
    for string in strings
  ]
  maximum = max(counts)
  index = counts.index(maximum)
  return chr(index)

def findXORkey(bytelist):
  #Determine the single most likely key
  xor_bytes = [[b ^ ord(character) for b in bytelist] for character in [chr(x) for x in range(128)]]
  xor_strings = [''.join(list(map(chr, integer))) for integer in xor_bytes]
  key = detectKey(xor_strings)
  return key

def findCipherKey(text):
  #Find the cipher key that was used to XOR encrypt the input text
  key_size = find_key_size(text)
  transposed_bytes = transpose(text, key_size)
  vignere_key = ''.join([findXORkey(x) for x in transposed_bytes])
  return vignere_key

def decryptCipher(ciphertext, key):
  #Decrypt with cipher
  bytes_text = b64decode(ciphertext)
  bytes_key = bytearray.fromhex(key.encode('utf-8').hex())
  decrypted_bytes = [
    b ^ bytes_key[i % len(bytes_key)] for i, b in enumerate(bytes_text)
  ]
  decrypted_characters = [chr(b) for b in decrypted_bytes]
  decrypted_text = ''.join(decrypted_characters)
  return decrypted_text

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
#ciphertext_hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
#plaintext = SingleByteXOR(ciphertext_hex_str)
#print(plaintext)

#testing challenge 4
#result = detectSingleXOR_file('txt_chall4.txt')
#print(result['key'], result['plaintext'], result['score'])

#testing challenge 5
#plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
#key = "ICE"
#print(bytesToHex(repeatingXOR(plaintext.encode(), key)))

#testing challenge 6
str1 = "this is a test"
str2 = "wokka wokka!!!"
print (hammingDist(bytearray.fromhex((str1).encode('utf-8').hex()), (bytearray.fromhex((str2).encode('utf-8').hex()))))
#test that code works so far, we should get 37 and we do!
url = "https://cryptopals.com/static/challenge-data/6.txt" 
ciphertext = run(['curl', '--silent', url]).decode('ascii')
key = findCipherKey(ciphertext)
message = decryptCipher(ciphertext, key)
print("Key:", key)
print(message)
