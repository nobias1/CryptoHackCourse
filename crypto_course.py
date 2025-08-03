import base64

# Converting numbers to ASCII using the chr() function
asciiNums = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
for i in asciiNums:
    print(chr(i))

# Converting hexString to Bytes
hexString = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'

fromHex = bytes.fromhex(hexString)
print("Original hex string converted to bytes: " + str(fromHex) + '\n')

# Converting Bytes string back to Hex
fromHexToBytes = bytes.hex(fromHex)
print("Bytes string converted back to hex: " + str(fromHexToBytes))
print(str(hexString) + '\n')

# Checking if both strings match
if str(fromHexToBytes) == hexString:
    print("Both strings match. Conversion successful" + '\n')
else:
    print("The 2 strings do not match" + '\n')

# Now we have to convert fromhexToBytes to Base64
fromBytestoB64 = base64.b64encode(fromHex)
print(fromBytestoB64)


'''
CryptoHacks Explanation for converting messages to numbers as seen in the RSA Public-Key Cryptography Standards:

How should we convert our messages into numbers so that mathematical operations can be applied?
The most common way is to take the ordinal bytes of the message, convert them into hexadecimal, and concatenate. This can be interpreted as a base-16/hexadecimal number, and also represented in base-10/decimal.

My understanding:
RSA uses Octet String to Integer Primitive or "OS2IP". This algorithm converts strings to numbers in the following way.
    1. First consider "HELLO", as a sequence of numerical byte values: [72, 69, 76, 76, 79].
    2. Then, these byte values are "glued" together in the following manner:
        The calculation is:
(72 * 256⁴) + (69 * 256³) + (76 * 256²) + (76 * 256¹) + (79 * 256⁰)

Let's do the math:
72 * 4,294,967,296 = 309,237,645,312

69 * 16,777,216 = 1,157,627,904

76 * 65,536 = 4,980,736

76 * 256 = 19,456

79 * 1 = 79
Adding them all up:
309,237,645,312 + 1,157,627,904 + 4,980,736 + 19,456 + 79 = 310,400,273,487

This is done with PyCryptodomes bytes_to_long() function. The reverse is done with long _to_bytes().

The Reverse Process: Division and Remainder
While bytes_to_long() uses multiplication and addition, long_to_bytes() uses their opposites: division and remainder (modulo). It repeatedly divides the large number by 256 and records the remainder at each step to reconstruct the original bytes.

Here’s how it works on our big number, 310400273487:

Step 1:
310400273487 % 256 gives a remainder of 79 (the byte for 'O').
The number becomes 310400273487 // 256 = 1212501068.

Step 2:
1212501068 % 256 gives a remainder of 76 (the byte for 'L').
The number becomes 1212501068 // 256 = 4736332.

Step 3:
4736332 % 256 gives a remainder of 76 ('L').
The number becomes 4736332 // 256 = 18501.

Step 4:
18501 % 256 gives a remainder of 69 ('E').
The number becomes 18501 // 256 = 72.

Step 5:
72 % 256 gives a remainder of 72 ('H').
The number becomes 72 // 256 = 0. The process stops.

The function collects these remainders ([79, 76, 76, 69, 72]) and reverses them to get the original big-endian sequence: [72, 69, 76, 76, 79], which is the message "HELLO".
'''
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
print('\n' + 'Challenge 6: Bytes and Big Integers')
from Crypto.Util.number import *

# bytes_to_long() to convert a message to numbers
# long_to_bytes() to do the reverse

revstring = long_to_bytes(11515195063862318899931685488813747395775516287289682636499965282714637259206269)
print(revstring)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# XOR Starter
# https://cryptohack.org/courses/intro/xor0/
# XOR is a bitwise operator which returns 0 if the bits are the same, and 1 otherwise. In textbooks the XOR operator is denoted by ⊕, but in most challenges and programming languages you will see the caret ^ used instead
print('\n' + 'Challenge 7: XOR Starter')
xorString = 'label'
xorStringChars = list(xorString)
print(xorStringChars)

# Convert list of characters to list of Unicode values using ord() function
unicodeConversion = []
counter = 0
for i in xorStringChars:
    print(ord(i))
    unicodeConversion.insert(counter, ord(i))
    counter += 1 
#    print(counter)

print(unicodeConversion)

# XOR each value in unicodeConversion
convertNewValsToString = []
for i in unicodeConversion:
    print(i ^ 13)
    newval = i ^ 13
    convertNewValsToString.insert(counter, newval)
    counter += 1
print(convertNewValsToString)

# Convert list of Unicode values back to Strings using chr() function
for i in convertNewValsToString:
    print(chr(i))

# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# XOR Properties
# https://cryptohack.org/courses/intro/xor1/
print('\n' + 'Challenge 8: XOR Properties')
# KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
# KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
# KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
# FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

# KEY2 ^ KEY1 seems redundant based on the properties explained in this section
key1 = 'a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313'
key3 = 'c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1'
key4 = '04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf'
# Converting to bytes
key1ToBytes = bytes.fromhex('a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313')
key3ToBytes = bytes.fromhex('c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1')
key4ToBytes = bytes.fromhex('04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf')
# so if I XOR key1 and key3 together, and then XOR this to key4, KEYS 1 2 and 3 SHOULD cancel out leaving us the flag... right?
print(key1ToBytes)
print(key3ToBytes)
print(key4ToBytes)
print(zip(key1ToBytes,key3ToBytes,key4ToBytes))

# XORing each byte one at a time for key1, key3, and key4, and then 
flagBytes = bytes(b1 ^ b3 ^ b4 for b1, b3, b4 in zip(key1ToBytes,key3ToBytes,key4ToBytes))
print(flagBytes)
                  
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# Favourite Byte
print('\n' + 'Challenge 9: Favourite Byte')
favByte = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
print(favByte)

# This function XOR's 256 byte values against favByte and then 
# only outputs the result if all characters decode to ASCII
from pwn import xor
for i in range(256):
    result = xor(favByte, i)
    try:
        decodedString = result.decode('ascii')
        if all(32 <= ord(j) <= 126 for j in decodedString):
            print('Key: ' + str(i) + ' ' + 'String: ' + decodedString)
    except UnicodeDecodeError:
        continue

# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------------------------------------------
# Favourite Byte
# This challenge is interesting because you're discovering *parts* of the key first based on what you know it might already contain. eg. crypto{}
print('\n' + 'Challenge 10: You either know, XOR you dont')

hexString2 = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'
hexString2Bytes = bytes.fromhex('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104')
keyBytes = b"crypto{"
print(xor(hexString2Bytes, keyBytes).decode())

newKeyBytes = b"myXORkey"
print(xor(hexString2Bytes, newKeyBytes).decode())
