import hashlib

#Password input and salt
password = input('Enter password: ')
salt = ("yrPwd123")

#Hash password and salt with md5
password_hash_md5 = (hashlib.md5(password.encode('utf-8')).hexdigest())
salt_hash_md5 = (hashlib.md5(salt.encode('utf-8')).hexdigest())
#Combine and hash with md5
join_hash_md5 = password_hash_md5 + salt_hash_md5
hash_md5 = (hashlib.md5(join_hash_md5.encode('utf-8')).hexdigest())
#Add 10 iterations to md5
hash10_md5 = (hashlib.pbkdf2_hmac('md5', b'password_hash_md5', b'salt_hash_md5', 10).hex)

#Hash password and salt with sha256
password_hash_sha256 = (hashlib.sha256(password.encode('utf-8')).hexdigest())
salt_hash_sha256 = (hashlib.sha256(salt.encode('utf-8')).hexdigest())
#Combine and hash with sha256
join_hash_sha256 = password_hash_sha256 + salt_hash_sha256
hash_sha256 = (hashlib.sha256(join_hash_sha256.encode('utf-8')).hexdigest())
#Add 10 iterations to sha256
hash10_sha256 = (hashlib.pbkdf2_hmac('sha256', b'password_hash_sha256', b'salt_hash_sha256', 100).hex)

#Hash password and salt with sha512
password_hash_sha512 = (hashlib.sha512(password.encode('utf-8')).hexdigest())
salt_hash_sha512 = (hashlib.sha512(salt.encode('utf-8')).hexdigest())
#Combine and hash with sha512
join_hash_sha512 = password_hash_sha512 + salt_hash_sha512
hash_sha512 = (hashlib.sha512(join_hash_sha512.encode('utf-8')).hexdigest())
#Add 10 iterations to sha512
hash10_sha512 = (hashlib.pbkdf2_hmac('sha512', b'password_hash_sha512', b'salt_hash_sha512', 100).hex)

#Print data
print()
print("Password is : " + password)
print("Salt is : " + salt)

#Print md5 hash
print()
print("md5")
print("Password = " + password_hash_md5)
print("Salt     = " + salt_hash_md5)
print("Joined   = " + hash_md5)
print("10 Iterations = " + str(hash10_md5))

#Print sha256 hash
print()
print("sha256")
print("Password = " + password_hash_sha256)
print("Salt     = " + salt_hash_sha256)
print("Joined   = " + hash_sha256)
print("10 Iterations = " + str(hash10_sha256))

#Print sha512 hash
print()
print("sha512")
print("Password = " + password_hash_sha512)
print("Salt     = " + salt_hash_sha512)
print("Joined   = " + hash_sha512)
print("10 Iterations = " + str(hash10_sha512))