import hashlib

def md5_crack(hash_to_crack, wordlist):
    with open(wordlist, 'r') as file:
        for line in file:
            word = line.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                return word
    return "Hash not found."

hash_to_crack = "5f4dcc3b5aa765d61d8327deb882cf99"  # Example hash (md5 of 'password')
wordlist_path = "wordlist.txt"  # Path to your wordlist file
result = md5_crack(hash_to_crack, wordlist_path)

print(f"Cracked Hash: {result}")
