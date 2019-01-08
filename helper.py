import math 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
from decimal import *

class Helper:

	@staticmethod
	def one_to_two_dimension(index, N):
		root_N = int(math.ceil(N**(0.5)))
		row = index // root_N
		col = index % root_N
		return(row, col)

	@staticmethod
	def two_to_one_dimension(row, col, N):
		root_N =  int(math.ceil(N**(0.5)))
		return row * root_N + col

	@staticmethod
	def encrypt_old(x_key, y_key, w):
	    c_x = Cipher(algorithms.AES(x_key), modes.CTR(b'\x00'*16), default_backend()).encryptor()
	    c_y = Cipher(algorithms.AES(y_key), modes.CTR(b'\x00'*16), default_backend()).encryptor()
	    return c_x.update(c_y.update(w) + c_y.finalize()) + c_x.finalize()

	@staticmethod
	def decrypt_old(x_key, y_key, e):
	    c_x = Cipher(algorithms.AES(x_key), modes.CTR(b'\x00'*16), default_backend()).decryptor()
	    c_y = Cipher(algorithms.AES(y_key), modes.CTR(b'\x00'*16), default_backend()).decryptor()
	    return c_y.update(c_x.update(e) + c_x.finalize()) + c_y.finalize()

	@staticmethod
	def encrypt_fernet(key, num):
		salt = bytes(bytearray(16))
		password_bytes = bytes([key])
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
   				length=32,
    			salt=salt,
     			iterations=1000,
    			backend=default_backend()
 			)
 		key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
 		f = Fernet(key)
		token = f.encrypt(bytes([num]))
		return token

	@staticmethod
	def decrypt_fernet(key, ct):
		salt = bytes(bytearray(16))
		password_bytes = bytes([key])
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
   				length=32,
    			salt=salt,
     			iterations=1000,
    			backend=default_backend()
 			)
 		key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
 		f = Fernet(key)
 		try:
	 		dec_id = f.decrypt(ct)
			dec_id = int(dec_id[1:-1])
			return dec_id
		except cryptography.fernet.InvalidToken:
			return -1
		
	@staticmethod
	def encrypt(key, num):
		return key ^ num

	@staticmethod
	def decrypt(key, ct):
		return key ^ ct
