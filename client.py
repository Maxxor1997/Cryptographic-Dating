import random		
from helper import Helper

class Client(object):

	def __init__(self, id, N, k, g, p):
		self.id = id
		self.N = N
		self.k = k
		self.g = g
		self.p = p

		# randomly chosen preference for k other persons
		self.preferences = []
		for i in range(k):
			rand_int = random.randint(0, N)
			while rand_int == self.id or rand_int in self.preferences:
				rand_int = random.randint(0, N)
			self.preferences.append(rand_int)

		# randomly chose private key
		self.private_key = random.randint(1, 101)

	def generate_key_ex_part_one(self):
		return (self.g**self.private_key) % self.p

	def receive_encrypted_entries(self, encrypted_entries):
		self.encrypted_entries = encrypted_entries


	# 1-2 OT transfer
	def one_two_OT_one(self, A, choice, g):
		self.b = random.randint(1, 101)
		self.key = (A**self.b) 
		if choice == 0:
			return (g**self.b) 
		if choice == 1:
			return (A*(g**self.b)) 
		return -1
	def one_two_OT_two(self, m0, m1, choice, g):
		if choice == 0:
			return m0 ^ self.key 
		else:
			return m1 ^ self.key

	# 1-N OT transfer
	def one_N_OT_one(self):
		return 0

