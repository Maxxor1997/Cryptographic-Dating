from time import time
import timeit
import random
import unittest
from client import Client
from server import Server
from helper import Helper
import math


class CryptoDatingTest(unittest.TestCase):

	def setUp(self):
		# g and p for the DH key exchange
		self.g = 5
		self.p = 23

	def test_basic(self):

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
		print(choice, m)

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
		print(choice, m)

	# simulate 1-N OT
	def one_N_OT(self, server, client, secrets, choice):
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
		# total number of clients
		N = 9
		# number of preferences allowed
		k = 2

		server = Server(N, k, self.g, self.p)
		client = Client(0, N, k, self.g, self.p)
		g = 7

		secrets = [0, 1, 2, 3, 4, 5, 6, 7, 8]
		self.preferences = []
		for i in range(k):
			rand_int = random.randint(0, N)
			while rand_int == self.id or rand_int in self.preferences:
				rand_int = random.randint(0, N)
			self.preferences.append(rand_int)

		encrypted_secrets = server.k_N_OT_one(secrets)

		# simulate client behavior here
		



if __name__ == '__main__':
    unittest.main()