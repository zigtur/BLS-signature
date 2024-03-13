# BN128 Elliptic Curve

## Definition

First, let's define the name of this elliptic curve.
Multiple names for this curve are defined, that may become confusing.
The elliptic curve we are talking about can be named[^1]:
- **BN128**: "BN" stands for Barreto-Naehrig, and "128" is the theoretical bits of security
- **alt_BN128**: Why? Why not.
- **BN254**: "254" referring to the number of bits in the prime associated to the base field.

*Note: The elliptic curve we are talking about is not the one referenced at this link: https://neuromancer.sk/std/bn/bn254*

## Introduction

**BN128** is a **Barreto-Naehrig** curve that is known as pairing friendly.
This curve was previously considered with **128**-bit
of security. But this number of bits dropped to around **100** bits after new algorithms
were published in 2015 by Taechan Kim and Razvan Barbulescu[^2].

It was previously used by ZCash and is currently implemented on Ethereum[^3][^4] through 3 precompiled contracts
(1 for addition, 1 for multiplication and 1 for pairing).
It is the most pairing friendly curve used for verifying on-chain zkSNARKs using proof schemes such as
Groth16[^5] and Plonk[^6].

Another similar curve is BLS12-381[^7] which provides more bits of security.

### Barreto-Naherig curve

A Barreto-Naherig[^8] curve is an elliptic curve *E* of the form:
$$Y^2 = X^3 + b$$

It is defined over a prime field $F_p$ for a parameter $x$, where the prime $p$ is defined as:
$$p = 36x^4 + 36x^3 + 24x^2 + 6x + 1$$

The $x$ parameter also determines other interesting constants for the curve $E$:
$$r = 36x^4 + 36x^3 + 18x^2 + 6x + 1$$
$$t = 6x^2 + 1$$

$x$ is chosen to get $r$ a prime number and $t$ is called the *trace of Frobenius* of the curve.


## Mathematical definition

The equation of the BN128 elliptic curve is:
$$Y^2 = X^3 + 3$$

It is defined over the field $F_p$ with:
$$p = 21888242871839275222246405745257275088696311157297823662689037894645226208583$$

The parameter $x$ for BN128 is:
$$x = 4965661367192848881$$

Then, the following equation must be true:
$$36x^4 + 36x^3 + 24x^2 + 6x + 1 = p$$
$$(36 * 4965661367192848881)^4 + (36*4965661367192848881)^3 + (24*4965661367192848881)^2 + 6 * 4965661367192848881 + 1 = 21888242871839275222246405745257275088696311157297823662689037894645226208583$$


Then, the curve order $r$ is:
$$36x^4 + 36x^3 + 18x^2 + 6x + 1 = r$$
$$(36 * 4965661367192848881)^4 + (36*4965661367192848881)^3 + (18*4965661367192848881)^2 + 6 * 4965661367192848881 + 1 = 21888242871839275222246405745257275088548364400416034343698204186575808495617$$


|  | alt_bn128 | BLS12-381 | Note |
| --- | --- | --- | --- |
| $F_p$ | 254 bits (32 bytes) | 381 bits (48 bytes) | has leading zero bits |
| $F_{p^2}$ | 64 bytes | 96 bytes |  |
| $\Bbb G_1$ Uncompressed | 64 bytes | 96 bytes | x and y coordinates as $F_{p}$ |
| $\Bbb G_2$ Uncompressed | 128 bytes | 192 bytes | x and y coordinates as $F_{p^2}$ |

But $\Bbb G_1$ and $\Bbb G_2$ points can be compressed.

|  | alt_bn128 | BLS12-381 |
| --- | --- | --- |
| $\Bbb G_1$ compressed | 32 bytes | 48 bytes |
| $\Bbb G_2$ compressed | 64 bytes | 96 bytes |


## BLS signature with BN128

*Note: This part assumes knowledge of elliptic curve pairing.*

BLS signature works with two groups $\Bbb G_1$ and $\Bbb G_2$.
This type of signature require to have the public key in a group
and the signature in the other.

The developer is able to choose between two options:
- Small $\Bbb G_1$ public keys with big $\Bbb G_2$ signatures
- Big $\Bbb G_2$ public keys with small $\Bbb G_1$ signatures

In the following details, we take $\Bbb G_2$ pubkeys and $\Bbb G_1$ signatures.

### Theoretical details

#### Hash function

First, the message is mapped to an element of G1.

$$H_0: \mathcal{M} \to \Bbb G_1$$

#### Key Generation

Secret Key:

$$\alpha \gets \Bbb Z_q$$

Public Key:

$$h \gets \alpha \times G_2 \in \Bbb G_2$$

#### Signing

$$\sigma \gets \alpha \times H_0(m) \in \Bbb G_1$$

#### Verification

$$e(\sigma, G_2)\stackrel{?}{=} e(H_0(m), h)$$

#### Proof of Verification

$$e(\sigma, G_2) \\= e( \alpha \times H_0(m), G_2) \\= e(  H_0(m), \alpha \times G_2) \\= e(H_0(m), h)$$

### Hands-on tests

#### Python example

We take $\Bbb G_2$ pubkeys and $\Bbb G_1$ signatures.

Requirements:
```bash
pip3 install py_ecc pycryptodome
```

Two python scripts are available:
- [`bls-signature.py`](./bn128-python/bls-signature.py): uses the BLS signature scheme of py_ecc
- [`bn128_bls-signature.py`](./bn128-python/bn128_bls-signature.py): implements its own BLS signature algorithm, with G1 signature and G2 pubkey for verification
- [`bn128_bls-multisig.py`](./bn128-python/bn128_bls-multisig.py): implements its own BLS multisignature scheme, with G2 signature and G1 pubkey for verification
- [`bn128_bls-multisig-handling-nonsigners.py`](./bn128-python/bn128_bls-multisig-handling-nonsigners.py): implements its own BLS multisignature scheme, with G1 signature and G2 pubkey for verification. It shows how to handle non-signers in the multisignature scheme.

#### Solidity example

*Note: TODO*

A Solidity example[^9] is available.

It is based on Foundry.

Requirements:
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
# Update Foundry
foundryup
# Then launch test
forge test
```

## Sources

[^1]: *"BN254 For The Rest Of Us"*, https://hackmd.io/@jpw/bn254

[^2]: *"Extended Tower Number Field Sieve: A New Complexity for the Medium Prime Case"*, https://eprint.iacr.org/2015/1027.pdf

[^3]: *"EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128"*, https://eips.ethereum.org/EIPS/eip-196

[^4]: *"EIP-197: Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128"*, https://eips.ethereum.org/EIPS/eip-197

[^5]: *"On the Size of Pairing-based Non-interactive Arguments"*, https://eprint.iacr.org/2016/260.pdf

[^6]: *"PlonK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"*, https://eprint.iacr.org/2019/953.pdf

[^7]: *"BLS12-381 For The Rest Of Us"*, https://hackmd.io/@benjaminion/bls12-381

[^8]: *"Pairing-Friendly Elliptic Curves of Prime Order"*, https://www.cryptojedi.org/papers/pfcpo.pdf

[^9]: *"BLS Signatures in Solidity"*, https://hackmd.io/@liangcc/bls-solidity

