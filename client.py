import random		
from helper import Helper

class Client(object):

	def __init__(self, id, N, k, g, p):
		self.id = id
		self.N = N
		self.k = k
		self.g = g
		self.p = p
		self.completed_keys = []
		self.matches = []

		# randomly chosen preference for k other persons
		self.preferences = []
		for i in range(k):
			rand_int = random.randint(0, N-1)
			while rand_int == self.id or rand_int in self.preferences:
				rand_int = random.randint(0, N-1)
			self.preferences.append(rand_int)

		# randomly chose private key
		self.private_key = random.randint(1, 500)

	def generate_key_ex_part_one(self):
		self.key1 = (self.g**self.private_key) % self.p
		return (self.key1)

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
			return Helper.decrypt(self.key, m0)
		else:
			return Helper.decrypt(self.key, m1)

	# expose preferences to simulator
	def get_preferences(self):
		return self.preferences

	def get_matches(self):
		return self.matches

	def get_completed_keys(self):
		return self.completed_keys

	def update_with_entries(self, entries):
		for e in entries:
			self.completed_keys.append((e**self.private_key) % self.p)

	def broadcast(self):
		bs = []
		for k in self.completed_keys:
			bs.append(Helper.encrypt_fernet(k, self.id))
		return bs

	def receive_broadcast(self, bs):
		self.matches = []
		# try to decrypt every entry
		for b in bs:
			for k in self.completed_keys:
				dec = Helper.decrypt_fernet(k, b)
				if dec >= 0 and dec < self.N and dec != self.id and dec not in self.matches:
					self.matches.append(dec)
		return self.matches


