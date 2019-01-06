import random
import math
from helper import Helper
from hashlib import sha256
import hmac

class Server(object):

	def __init__(self, N, k, g, p):
		self.N = N
		self.root_N = int(math.ceil(self.N**(0.5)))

		# generate row randomizers
		self.row_rands = []
		for i in range(self.root_N):
			self.row_rands.append(random.randint(1, 101))

		# generate col randomizers
		self.col_rands = []
		for i in range(self.root_N):
			self.col_rands.append(random.randint(1, 101))

		self.k = k
		self.g = g
		self.p = p


	def receive_key_ex_part_one(self, entries):

		# save entries
		self.entries = entries

		# generate encrypted secrets
		self.encrypted_entries = []
		for i, entry in enumerate(self.entries):
			row, col = Helper.one_to_two_dimension(i, self.N)
			key = self.row_rands[row] ^ self.col_rands[col]
			encrypted_message = key ^ entry
			self.encrypted_entries.append(encrypted_message)

		return self.encrypted_entries


	# 1-2 OT transfer
	def one_two_OT_one(self, g):
		self.a = random.randint(1, 101)
		self.A = (g**self.a) 
		return self.A
	def one_two_OT_two(self, secrets, B, g):
		k0 = (B**self.a) 
		k1 = ((B/self.A)**self.a) 
		e0 = k0 ^ secrets[0]
		e1 = k1 ^ secrets[1]
		return e0, e1

	# 1-N OT transfer
	def one_N_OT_one(self, secrets):

		# generate l pairs of random keys
		l = int(math.ceil(math.log(len(secrets), 2)))
		self.keys = []
		for i in range(l):
			k0 = random.randint(1, 100)
			k1 = random.randint(1, 100)
			self.keys.append((k0, k1))

		# encrypt all keys
		encrypted_secrets = []
		for i, entry in enumerate(secrets):
			fmt_str = '{0:0' + str(l) + 'b}'
			bin_rep = fmt_str.format(i)
			key = 0
			for j, char in enumerate(bin_rep):
				key = key ^ self.keys[j][int(char)]
			encrypted_secrets.append(key ^ entry)

		return encrypted_secrets


	def k_N_OT_one(self, secrets):
		

	# allow simulator to access secrets
	def get_secrets(self, j):
		return self.keys[j]





