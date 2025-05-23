import os
from hashlib import blake2b
from hmac import compare_digest
from binascii import hexlify

def sign(public_data_hex, secret_key):
    public_data = public_data_hex.encode('utf-8')
    secret_key = secret_key.encode('utf-8')
    h = blake2b(digest_size=24, key=secret_key)
    h.update(public_data)
    return h.hexdigest()

def verify(public_data_hex, secret_key, sig):
    good_sig = sign(public_data_hex, secret_key)
    return compare_digest(good_sig, sig)

PUBLIC_KEY ="77c300e5871fa9889ead09d6562b2b430112c39abe205bde"
def create_key():
    return hexlify(os.urandom(24)).decode('utf-8')
SECRET_KEY = create_key()
