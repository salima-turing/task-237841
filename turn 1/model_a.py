import os

def encrypt_data(data: bytes, key: bytes) -> bytes:
	"""
	Encrypts data using a simple XOR encryption algorithm (for demonstration purposes only, not secure for real use).

	Args:
		data (bytes): The data to be encrypted.
		key (bytes): The encryption key.

	Returns:
		bytes: The encrypted data.
	"""
	result = b""
	for i in range(len(data)):
		result += bytes([data[i] ^ key[i % len(key)]])
	return result

def decrypt_data(encrypted_data: bytes, key:bytes) -> bytes:
	"""
	Decrypts encrypted data using the same XOR encryption algorithm as encrypt_data.

	Args:
		encrypted_data (bytes): The encrypted data to be decrypted.
		key (bytes): The decryption key.

	Returns:
		bytes: The decrypted data.
	"""
	return encrypt_data(encrypted_data, key)


if __name__ == "__main__":
	# Sensitive data should be handled as bytes
	sensitive_data = b"This is confidential information"

	# Generation of a secure key - In a real application, use a cryptographically secure method
	key = os.urandom(16)

	encrypted_data = encrypt_data(sensitive_data, key)

	# Perform the security test
	try:
		unauthorized_access_key = b"InvalidKey"
		decrypted_data_with_invalid_key = decrypt_data(encrypted_data, unauthorized_access_key)
		print("Error: Sensitive data decrypted with invalid key!")
		exit(1)
	except Exception as e:
		print(f"Expected Exception: {e}")
		print("Good: Confidentiality test passed. Sensitive data not decrypted with invalid key.")
