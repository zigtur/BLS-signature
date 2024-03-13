from py_ecc.optimized_bn128 import FQ, FQ2, FQ12, G1, G2, add, curve_order, is_on_curve, multiply, neg, pairing
from Crypto.Hash import keccak

print("----------------------\nIntroduction\n----------------------")

alice_secret_key = 5566
alice_G1_pubkey = multiply(G1, alice_secret_key)
alice_G2_pubkey = multiply(G2, alice_secret_key)

bob_secret_key = 984587909836787658789
bob_G1_pubkey = multiply(G1, bob_secret_key)
bob_G2_pubkey = multiply(G2, bob_secret_key)

print("""Alice Private Key = {}
G1 public key = {}
G2 public key = {}\n""".format(alice_secret_key, alice_G1_pubkey, alice_G2_pubkey))

print("""Bob Private Key = {}
Bob G1 public key = {}
Bob G2 public key = {}""".format(bob_secret_key, bob_G1_pubkey, bob_G2_pubkey))


print("\n----------------------\nAggregated Public Key\n----------------------")

print("To create the Aggregated Public Key (APK), an addition is made: Alice PubKey + Bob Pubkey")

apk_G1 = add(bob_G1_pubkey, alice_G1_pubkey)
apk_G2 = add(bob_G2_pubkey, alice_G2_pubkey) # G2 addition is way less efficient than G1 addition

print("G1 APK =", apk_G1)
print("G2 APK =", apk_G2)

gamma = 678546786567567398850 # random number
gamma_tester_G1 = multiply(apk_G1, gamma)
gamma_G1 = multiply(G1, gamma)

# e([gamma * sk]_1, [1]_2) == e([gamma]_1, [sk]_2)
apk_match = pairing(G2, gamma_tester_G1) == pairing(apk_G2, gamma_G1)

print("\nDoes G1 APK match G2 APK:", apk_match)


print("\n----------------------\nSignature generation\n----------------------")

text_to_sign = input("Enter your message to sign: ")

hashing = keccak.new(digest_bits=256)
hashing.update(bytes(text_to_sign, "UTF-8"))
hashed = int.from_bytes(hashing.digest(), "big" ) % curve_order

## G2 signature

alice_signature = multiply(G2, alice_secret_key * hashed)
bob_signature = multiply(G2, bob_secret_key * hashed)

print("Alice G2 Signature:", alice_signature)
print("Bob G2 Signature:", bob_signature)

apk_signature = add(alice_signature, bob_signature)

print("APK G2 Signature:", apk_signature)


print("\n----------------------\nSignature verification\n----------------------")

hash_G2 = multiply(G2, hashed)

# e([1]_1, [sk * H]_2) == e([sk]_1, [H]_2)
signature_result = pairing(apk_signature, G1) == pairing(hash_G2, apk_G1)

print("Signature is valid?", signature_result)
