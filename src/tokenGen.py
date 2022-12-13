import hashlib
import random

class SecretGenerator:
	def __init__(self, filename_a, filename_b, filename_c):
		self.filename_s0 = filename_a
		self.filename_s1 = filename_b
		self.filename_hash = filename_c
		self.token_a = ""
		self.token_a = ""
		self.preimage = ""
		self.hash = 0
	def gensecrets(self):
		self.token_a = random.getrandbits(256)
		self.token_a = format(self.token_a, 'b').zfill(256)
		self.token_b = random.getrandbits(256)
		self.token_b = format(self.token_b, 'b').zfill(256)
		print("Secrets: \n")
		print(self.token_a)
		print(self.token_b)
		with open(self.filename_s0, 'w') as f:
			f.write(self.token_a)
		with open(self.filename_s1, 'w') as f:
			f.write(self.token_b)
	def catsecrets(self):
		self.preimage = self.token_a + self.token_b
	def genhash(self):
		data = '%0128X' % int(self.preimage, 2)
		self.hash = hashlib.sha256(bytes.fromhex(data))
		# print the equivalent hexadecimal value.
		print("The hexadecimal equivalent of SHA256 is : ")
		print(self.hash.hexdigest())
		with open(self.filename_hash, 'w') as f:
			f.write(str(self.hash.hexdigest()))
		print ("\r")

if __name__ == "__main__":
	filename_s0 = "0.secret"
	filename_s1 = "1.secret"
	filename_hash = "y.hash"
	generator = SecretGenerator(filename_s0, filename_s1, filename_hash)
	generator.gensecrets()
	generator.catsecrets()
	generator.genhash()



