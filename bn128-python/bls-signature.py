from py_ecc.bls import G2ProofOfPossession as bls_pop
from Crypto.Hash import SHA3_256

private_key = 5566
public_key = bls_pop.SkToPk(private_key)


text_to_sign = input("Enter your message to sign: ")

hashing = SHA3_256.new()
hashing.update(bytes(text_to_sign, "UTF-8"))
hashed = hashing.digest()

# Signing
signature = bls_pop.Sign(private_key, hashed)

# Verifying
assert bls_pop.Verify(public_key, hashed, signature)