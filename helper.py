import math 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
	def encrypt(key, num):
		key = bytes([key])
		key = key.ljust(32, '\0')
		backend = default_backend()
		iv = bytes([0])
		iv = iv.ljust(16, '\0')
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		encryptor = cipher.encryptor()
		ct = encryptor.update(bytes([num])) + encryptor.finalize()
		return ct

	@staticmethod
	def decrypt(key, ct):
		key = bytes([key])
		key = key.ljust(32, '\0')
		backend = default_backend()
		iv = bytes([0])
		iv = iv.ljust(16, '\0')
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		decryptor = cipher.decryptor()
		m = decryptor.update(ct) + decryptor.finalize()
		return int(m)
		
