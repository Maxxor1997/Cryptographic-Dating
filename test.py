from time import time
import timeit
import random
import unittest
from client import Client
from server import Server
from helper import Helper
import math
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct
from decimal import *

class CryptoDatingTest(unittest.TestCase):

	def setUp(self):
		# g and p for the DH key exchange
		self.g = 7
		self.p = 5279

	def roundup(self, x):
		return int(math.ceil(x / 100000.0)) * 100000

	def test_basic(self):

		success = 0

		for i in range(100):

			# total number of clients
			N = 9
			# number of preferences allowed
			k = 2

			# initialize server and clients
			server = Server(N, k, self.g, self.p)
			clients = []
			for i in range(N):
				clients.append(Client(i, N, k, self.g, self.p)) 

			# entries are generated and sent to server, who encrypts them
			entries = []
			for i in range(N):
				entries.append(clients[i].generate_key_ex_part_one())
			encrypted_entries = server.receive_key_ex_part_one(entries)

			# print(encrypted_entries)

			# server sends encrypted secrets to everyone
			for i in range(N):
				clients[i].receive_encrypted_entries(encrypted_entries)

			# each client does OT with server for k keys
			for i in range(N):
				prefs = clients[i].get_preferences()
				m = []
				for p in prefs:
					row_secs, col_secs, v = server.k_N_OT_one(self.g)
					row, col = Helper.one_to_two_dimension(p, N)
					row_val = self.one_N_OT(server, clients[i], row_secs, row)
					col_val = self.one_N_OT(server, clients[i], col_secs, col)
					key = self.roundup(int(v**(row_val * col_val)))
					m.append(encrypted_entries[p] ^ key)
				clients[i].update_with_entries(m)

			# each client broadcasts
			bs = []
			for i in range(N):
				b = clients[i].broadcast()
				bs.extend(b)
		

			# server broadcasts to all clients
			for i in range(N):
				clients[i].receive_broadcast(bs)


			# print out everything
			succ = 0
			for i in range(N):
				prefs = clients[i].get_preferences()
				manual_matches = []
				for p in prefs:
					if i in clients[p].get_preferences():
						manual_matches.append(p)
				manual_matches = manual_matches
				matches = clients[i].get_matches()
				if(sorted(manual_matches) == sorted(matches)):
					succ += 1
				keys = clients[i].get_completed_keys()
				# print(i, prefs, keys, matches)
			if succ == N:
				success += 1

		print("basic successes: " + str(success))


	def test_one_two_OT(self):
		# total number of clients
		N = 9
		# number of preferences allowed
		k = 2

		server = Server(N, k, self.g, self.p)
		client = Client(0, N, k, self.g, self.p)
		g = 7

		secrets = [0, 1]
		choice = random.randint(0, 1)
		A = server.one_two_OT_one(g)
		B = client.one_two_OT_one(A, choice, g)
		e0, e1 = server.one_two_OT_two(secrets, B, g)
		m = client.one_two_OT_two(e0, e1, choice, g)
		self.assertTrue(choice == m)

	# simulate 1-2 OT
	def one_two_OT(self, server, client, secrets, choice):
		g = 7
		A = server.one_two_OT_one(g)
		B = client.one_two_OT_one(A, choice, g)
		e0, e1 = server.one_two_OT_two(secrets, B, g)
		m = client.one_two_OT_two(e0, e1, choice, g)
		return m

	def test_one_N_OT(self):
		# total number of clients
		N = 9
		# number of preferences allowed
		k = 2

		server = Server(N, k, self.g, self.p)
		client = Client(0, N, k, self.g, self.p)
		g = 7

		secrets = [0, 1, 2, 3, 4, 5, 6, 7, 8]
		choice = random.randint(0, 8)

		encrypted_secrets = server.one_N_OT_one(secrets)

		# simulate client behavior here
		key = 0
		l = int(math.ceil(math.log(len(secrets), 2)))
		fmt_str = '{0:0' + str(l) + 'b}'
		bin_rep = fmt_str.format(choice)
		for j, char in enumerate(bin_rep):
			secrets_2 = server.get_secrets(j)
			choice_2 = int(char)
			key = key ^ self.one_two_OT(server, client, secrets_2, choice_2)
		m = encrypted_secrets[choice] ^ key
		self.assertTrue(choice == m)

	# simulate 1-N OT
	def one_N_OT(self, server, client, secrets, choice):
		self.assertTrue(choice < len(secrets))
		g = 7
		encrypted_secrets = server.one_N_OT_one(secrets)
		# simulate client behavior here
		key = 0
		l = int(math.ceil(math.log(len(secrets), 2)))
		fmt_str = '{0:0' + str(l) + 'b}'
		bin_rep = fmt_str.format(choice)
		for j, char in enumerate(bin_rep):
			secrets_2 = server.get_secrets(j)
			choice_2 = int(char)
			key = key ^ self.one_two_OT(server, client, secrets_2, choice_2)
		m = encrypted_secrets[choice] ^ key
		return m

	def test_k_N_OT(self):
		success = 0

		for i in range(100):
			# total number of clients
			N = 9
			# number of preferences allowed
			k = 3

			server = Server(N, k, self.g, self.p)
			client = Client(0, N, k, self.g, self.p)

			secrets = [0, 1, 2, 3, 4, 5, 6, 7, 8]
			self.preferences = []
			for i in range(k):
				rand_int = random.randint(0, N-1)
				while rand_int == self.id or rand_int in self.preferences:
					rand_int = random.randint(0, N-1)
				self.preferences.append(rand_int)

			encrypted_secrets = server.receive_key_ex_part_one(secrets)
			m = []
			for p in self.preferences:
				row_secs, col_secs, v = server.k_N_OT_one(self.g)
				row, col = Helper.one_to_two_dimension(p, N)
				row_val = self.one_N_OT(server, client, row_secs, row)
				col_val = self.one_N_OT(server, client, col_secs, col)
				key = self.roundup(int(v**(row_val * col_val)))
				m.append(encrypted_secrets[p] ^ key)

			if(self.preferences == m):
				success += 1

		print("kn successes: " + str(success))


	def test_exponentiation(self):
		for i in range(10):
		 	r = random.randint(1,5)
		 	c = random.randint(1, 5)
		 	rr = random.randint(1, 5)
			cc = random.randint(1, 5)

			g = 3

			x = self.roundup(g**(rr * cc))
		
			y = g**(1.0/(r * c)) 
			
			z = self.roundup(y**(rr*r*cc*c))
			
			self.assertTrue(x == z)


	def test_fernet(self):
		password = random.randint(1, 10)
		iden = random.randint(1, 100)
		salt = bytes(bytearray(16))
		password_bytes = bytes([password])
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
   				length=32,
    			salt=salt,
     			iterations=100000,
    			backend=default_backend()
 			)
 		key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
 		f = Fernet(key)
		token = f.encrypt(bytes([iden]))
		dec_id = f.decrypt(token)
		dec_id = int(dec_id[1:-1])
		
		self.assertTrue(dec_id == iden)

	def test_fernet_helper(self):
		for i in range(100):
			password = random.randint(1, 10000)
			iden = random.randint(1, 10000)
			ct = Helper.encrypt_fernet(password, iden)
			dt = Helper.decrypt_fernet(password, ct)
			self.assertTrue(dt == iden)

	def test_fernet_helper_failure(self):
		for i in range(100):
			password = random.randint(1, 10000)
			pass2 = random.randint(1, 10000)
			iden = random.randint(1, 10000)
			ct = Helper.encrypt_fernet(password, iden)
			dt = Helper.decrypt_fernet(pass2, ct)
			self.assertTrue(dt == -1)





if __name__ == '__main__':
    unittest.main()