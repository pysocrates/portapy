import hashlib

def sha256_hash(string):
    """Return the SHA256 hash of the given string."""
    return hashlib.sha256(string.encode()).hexdigest()

def crack_sha256_hash(hash_to_crack, dictionary_file):
    """Attempt to crack the given SHA256 hash using a dictionary attack."""
    with open(dictionary_file, 'r') as file:
        for line in file:
            word = line.strip()
            if sha256_hash(word) == hash_to_crack:
                return word
    return None

# Example Usage
hash_to_crack = input("Enter the SHA256 hash: ")
dictionary_file = input("Enter the path to the dictionary file: ")

cracked_password = crack_sha256_hash(hash_to_crack, dictionary_file)

if cracked_password:
    print(f"Cracked!: {cracked_password}")
else:
    print("Try another dictionary. Nothing found.")
