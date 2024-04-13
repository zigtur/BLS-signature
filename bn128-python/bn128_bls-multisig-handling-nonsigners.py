from py_ecc.bn128 import FQ, FQ2, FQ12, G1, G2, add, curve_order, is_on_curve, multiply, neg, pairing
from Crypto.Hash import keccak

print("----------------------\nIntroduction\n----------------------")

alice_secret_key = 5566
alice_G1_pubkey = multiply(G1, alice_secret_key)
alice_G2_pubkey = multiply(G2, alice_secret_key)

bob_secret_key = 984587909836787658789
bob_G1_pubkey = multiply(G1, bob_secret_key)
bob_G2_pubkey = multiply(G2, bob_secret_key)


charlie_secret_key = 12345678
charlie_G1_pubkey = multiply(G1, charlie_secret_key)
charlie_G2_pubkey = multiply(G2, charlie_secret_key)

print("There are 3 signers: Alice, Bob and Charlie.")

print("\n----------------------\nAggregated Public Key\n----------------------")

print("The Aggregated Public Key (APK) is: Alice PubKey + Bob Pubkey + Charlie Pubkey")

apk_G1 = add(add(bob_G1_pubkey, alice_G1_pubkey), charlie_G1_pubkey)
apk_G2 = add(add(bob_G2_pubkey, alice_G2_pubkey), charlie_G2_pubkey) # G2 addition is way less efficient than G1 addition

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

## G1 signature

alice_signature = multiply(G1, alice_secret_key * hashed)
bob_signature = multiply(G1, bob_secret_key * hashed)

print("Alice G1 Signature:", alice_signature)
print("Bob G1 Signature:", bob_signature)

print("\nThe message was only signed by Alice and Bob, as Charlie is absent...\n")

apk_signature = add(alice_signature, bob_signature)

print("APK G1 Signature:", apk_signature)


print("\n----------------------\nSignature verification\n----------------------")

hash_G1 = multiply(G1, hashed)

# e([sk * H]_1, [1]_2) == e([H]_1, [sk]_2)
signature_result = pairing(G2, apk_signature) == pairing(apk_G2, hash_G1)

print("APK Signature is valid?", signature_result)

print("\nTo validate the signature of Alice and Bob, Charlie's pubkey must be substracted from the APK.")

tmp_apk_G2 = add(apk_G2, neg(charlie_G2_pubkey))
signature_result = pairing(G2, apk_signature) == pairing(tmp_apk_G2, hash_G1)
print("After substraction of Charlie's pubkey, APK Signature is valid?", signature_result)

