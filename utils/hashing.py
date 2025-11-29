import hashlib

def generate_sha256(data):
    # Hash functions are one-way
    sha_signature = hashlib.sha256(data.encode('utf-8')).hexdigest()
    return sha_signature