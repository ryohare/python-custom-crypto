import sys,os

# messerlenne twiser - not crypographically secure
from random import randint

debug = True 

#data dictionary of common text and CLI chars
# map ascii values to numerical values
encoded_dict = {
'a' : 1, 'b' : 2, 'c' : 3, 'd' : 4,
'e' : 5, 'f' : 6, 'g' : 7, 'h' : 8,
'i' : 9, 'j' : 10, 'k' : 11, 'l' : 12,
'm' : 13, 'n' : 14, 'o' : 15, 'p' : 16,
'q' : 17, 'r' : 18, 's' : 19, 't' : 20,
'u' : 21, 'v' : 22, 'w' : 23, 'x' : 24,
'y' : 25, 'z' :26, ' ' : 100, 'A' : 101,
'B' : 102, 'C' : 103, 'D' : 103, 'E' : 104,
'F' : 105, 'G' : 106, 'H' : 107, 'I' : 108,
'J' : 109, 'K' : 110, 'L' : 111, 'M' : 112,
'N' : 113, 'O' : 114, 'P' : 115, 'Q' : 116,
'R' : 117, 'S' : 118, 'T' : 119, 'U' : 120,
'V' : 121, 'W' : 122, 'X' : 123, 'Y' : 124,
'Z' : 125, '.' : 200, '/' : 201, '\\' : 202,
'$' : 203, '#' : 204, '@' : 205, '%' : 206,
'^' : 207, '*' : 208, '(' : 209, ')' : 210,
'_' : 211, '-' : 212, '=' : 213, '+' : 214,
'>' : 215, '<' : 216, '?' : 217, ';' : 218,
':' : 219, '\'' : 220, '\"' : 221, '{' : 222,
'}' : 223, '[' : 224, ']' : 225, '|' : 226,
'`' : 227, '~' : 228, '!' : 229, '0' : 300,
'1' : 301, '2' : 302, '3' : 303, '4' : 304,
'5' : 306, '6' : 307, '7' : 308, '8' : 309,
'9' : 310
}

def encode_from_str(pt):
	encoded_buff = []

	for i in pt:
		encoded_buff.append(encoded_dict[i])

	return encoded_buff

def encrypt(pt, key):

	# pick a much smaller range than 0 < n < max(int) to make it less an outlier
	# if crypto analysis is being performed on any of this data.
    iv = randint(311,457)

    # weak algo 3x + key
    cipher_stream = []

    # prepend the IV to the key to it can be used in the same function
    cipher_stream.append(iv)
    
    # composite key is made up of iv + key
    composite_key = iv + int(key)
    for i in pt:
        eb = (3 * i) + int(composite_key)
        cipher_stream.append(eb)

    return cipher_stream

def write_encrypted_buff_to_file(filename, ct):
	with open( filename, 'w' ) as f:
		f.write(str(ct))

def encrypt_to_file(pt, key, filename):
	if debug:
		print("Encrypting:\n\t{}".format(pt))

	# encode the string to a normalized format
	encoded_buff = encode_from_str(pt)

	if debug:
		print("Encoded string:\n\t{}".format(str(encoded_buff)))

	# encrypt the encoded buffer with the algorithm
	encrypted_buff = encrypt(encoded_buff, key)

	if debug:
		print("Encrypted string:\n\t{}".format(encrypted_buff))

	# write out the data
	write_encrypted_buff_to_file(filename, encrypted_buff)

def load_file(filename):
	with open( filename, 'r' ) as f:
		raw_buff = f.read()

	raw_buff = raw_buff.split(',')
	raw_buff[0] = raw_buff[0][1:]
	raw_buff[len(raw_buff)-1] = raw_buff[len(raw_buff)-1][:-1]
	new_buff = []
	for i in raw_buff:
		new_buff.append(int(i))
	return new_buff

def decrypt(ct, key):
	# pull off the iv
	iv = ct[0]
	
	# rebuild the key from the iv and shared key
	composite_key = int(iv) + int(key)

	decrypted_buff = []

	# advance the buffer over the iv
	ct = ct[1:]
	for i in ct:
		decrypted_buff.append(int(
			( i - int(composite_key) ) / 3
		)) 
	return decrypted_buff

def decode_to_char_buff(enc):
	decoded = []
	for i in enc:
		for k,v in encoded_dict.items():
			if v == i:
				decoded.append(k)
	return decoded

def decrypt_file(filename, key):
	# load the file from disk
	file_buff = load_file(filename)

	if debug:
		print("Encrypted string:\n\t{}".format(file_buff))
	
	# decryt the buff to the encoded format
	enc_buff = decrypt(file_buff, key)

	if debug:
		print("Encoded string:\n\t{}".format(enc_buff))

	# decode the buffer
	char_buff = decode_to_char_buff(enc_buff)

	if debug:
		print("Char buffer:\n\t{}".format(char_buff)) 

	# make it a string to return
	return "".join(char_buff)

encrypt_to_file("this is a test", 127, "enct.cpt")

print(decrypt_file("enct.cpt", 127))

"""
ct = chowencrypt("this is a test",127)
print("encrypted string is {}".format(ct))

with open( 'cipher_text.crypt', 'w' ) as f:
    f.write(str(ct))

new_buff = load_file('cipher_text.crypt')

db = chowdecrypt(new_buff, 127)
print(str(db))
print(str(decode_to_char_buff(db)))
print("".join(decode_to_char_buff(db)))
"""
