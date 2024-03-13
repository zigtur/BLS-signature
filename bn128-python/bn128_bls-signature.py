from py_ecc.optimized_bn128 import FQ, FQ2, FQ12, G1, G2, add, curve_order, is_on_curve, multiply, neg, pairing
from Crypto.Hash import SHA3_256

print("----------------------\nIntroduction\n----------------------")

secret_key = 5566
G1_public_key = multiply(G1, secret_key)
G2_public_key = multiply(G2, secret_key)

print("""Private Key = {}
G1 public key = {}
G2 public key = {}""".format(secret_key, G1_public_key, G2_public_key))

print("\n----------------------\nPublic keys matching\n----------------------")

print("Matching of G1 public key to G2 public key can be tested through pairing.")

gamma = 678546786567567398850 # random number
gamma_tester_G1 = multiply(G1_public_key, gamma)
gamma_G1 = multiply(G1, gamma)

# e([gamma * sk]_1, [1]_2) == e([gamma]_1, [sk]_2)
pubkey_match = pairing(G2, gamma_tester_G1) == pairing(G2_public_key, gamma_G1)

print("G1 pubkey matches G2 pubkey:", pubkey_match)


print("\n----------------------\nSignature generation\n----------------------")

text_to_sign = input("Enter your message to sign: ")

hashing = SHA3_256.new()
hashing.update(bytes(text_to_sign, "UTF-8"))
hashed = int.from_bytes(hashing.digest(), "big" ) % curve_order

## G1 signature

signature = multiply(G1, secret_key * hashed)
# not_equivalent = multiply(G1_public_key, hashed)

print("G1 Signature:", signature)


print("\n----------------------\nSignature verification\n----------------------")

hash_G1 = multiply(G1, hashed)

# e([sk * H]_1, [1]_2) == e([H]_1, [sk]_2)
signature_result = pairing(G2, signature) == pairing(G2_public_key, hash_G1)

print("Signature is valid?", signature_result)
