import unittest
import hashlib
import tokenGen


class TestTokenGen(unittest.TestCase):
	def test_catsecrets(self):
		filename_s0 = "0.secret"
		filename_s1 = "1.secret"
		filename_hash = "y.hash"
		generator = tokenGen.SecretGenerator(filename_s0, filename_s1, filename_hash)
		generator.token_a = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		generator.token_b = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
		generator.catsecrets()
		catexpected = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
		self.assertEqual(generator.preimage, catexpected)
	def test_genhash(self):
		filename_s0 = "0.secret"
		filename_s1 = "1.secret"
		filename_hash = "y.hash"
		generator = tokenGen.SecretGenerator(filename_s0, filename_s1, filename_hash)
		generator.token_a = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		generator.token_b = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
		generator.catsecrets()
		generator.genhash()
		hashexpected =  'bba91ca85dc914b2ec3efb9e16e7267bf9193b14350d20fba8a8b406730ae30a'
		self.assertEqual(generator.hash.hexdigest(), hashexpected)

if __name__ == "__main__":
	unittest.main()




