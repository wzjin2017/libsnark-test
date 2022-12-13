import hashlib
import random

filename_a = "0.secret"
filename_b = "1.secret"
filename_c = "y.hash"
token_a = ""
token_b = ""
# for i in range(256):
# 	token_a += str(random.randint(0, 1))
# 	token_b += str(random.randint(0, 1))
token_a = random.getrandbits(256)
token_a = format(token_a, 'b').zfill(256)
token_b = random.getrandbits(256)
token_b = format(token_b, 'b').zfill(256)
print(token_a)
print(token_b)
#token_a = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
#token_b = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
preimgage = token_a + token_b
with open(filename_a, 'w') as f:
	f.write(token_a)
with open(filename_b, 'w') as f:
	f.write(token_b)

data = '%0128X' % int(preimgage, 2)
#print(data)
# then sending to SHA256()
result = hashlib.sha256(bytes.fromhex(data))
  
# printing the equivalent hexadecimal value.
print("The hexadecimal equivalent of SHA256 is : ")
print(result.hexdigest())
with open(filename_c, 'w') as f:
	f.write(str(result.hexdigest()))

print ("\r")
