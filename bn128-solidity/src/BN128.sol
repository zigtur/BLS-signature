// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import "../lib/forge-std/src/console2.sol";

library BN128Verifier {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[1] * i + X[0]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function G1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// Generator point in F_p2
    uint256 internal constant x1G2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant x0G2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant y1G2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant y0G2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    function G2() internal pure returns (G2Point memory) {
        return G2Point([x1G2, x0G2], [y1G2, y0G2]);
    }

    /// Negative generator G2
    uint256 internal constant x1nG2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant x0nG2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant y1nG2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 internal constant y0nG2 =
        13392588948715843804641432497768002650278120570034223513918757245338268106653;

    function negG2() internal pure returns (G2Point memory) {
        return G2Point([x1nG2, x0nG2], [y1nG2, y0nG2]);
    }

    function add(
        G1Point memory a,
        G1Point memory b
    ) internal view returns (G1Point memory output) {
        uint256[4] memory input;
        input[0] = a.X;
        input[1] = a.Y;
        input[2] = b.X;
        input[3] = b.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(gas(), 6, input, 0x80, output, 0x40)
        }

        require(success, "alt_bn128: add failed");
    }

    function mul(
        G1Point memory a,
        uint256 scalar
    ) internal view returns (G1Point memory output) {
        uint256[3] memory input;
        input[0] = a.X;
        input[1] = a.Y;
        input[2] = scalar;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(gas(), 7, input, 0x60, output, 0x40)
        }

        require(success, "alt_bn128: mul failed");
    }

    function pairing(
        G1Point memory a,
        G2Point memory b,
        G1Point memory c,
        G2Point memory d
    ) internal view returns (bool output) {
        uint256[12] memory input;
        input[0] = a.X;
        input[1] = a.Y;
        input[2] = b.X[0];
        input[3] = b.X[1];
        input[4] = b.Y[0];
        input[5] = b.Y[1];
        input[6] = c.X;
        input[7] = c.Y;
        input[8] = d.X[0];
        input[9] = d.X[1];
        input[10] = d.Y[0];
        input[11] = d.Y[1];
        bool success;

        // reuse the first input parameter in memory as the output
        assembly {
            success := staticcall(gas(), 8, input, 0x180, input, 0x20)
        }
        require(success, "alt_bn128: pairing failed");
        output = input[0] != 0;
    }

    function verifyPubkeyMatching(
        G1Point memory publicKeyG1,
        G2Point memory publicKeyG2
    ) public view returns (bool valid) {
        // get a pseudorandom, timestamp is not required
        uint256 pseudorandom = uint256(keccak256(abi.encode(publicKeyG1, publicKeyG2, block.timestamp, block.prevrandao)));
        G1Point memory keyTester = mul(G1(), pseudorandom);

        // pairing to verify matching between keys
        // e([gamma * sk]_1, [1]_2) + e([gamma]_1, [sk]_2) == 0
        valid = pairing(mul(publicKeyG1, pseudorandom), negG2(), keyTester, publicKeyG2);

        require(valid, "Mismatch: publicKeyG1 / publicKeyG2");
    }

    function verifySignature(
        G1Point memory publicKeyG1,
        G2Point memory publicKeyG2,
        G1Point memory signature,
        uint256 sigHash
    ) public view returns (bool valid) {
        // Check publicKeyG1/publicKeyG2 matching, reverts if doesn't match

        verifyPubkeyMatching(publicKeyG1, publicKeyG2);

        // get a pseudorandom for signature verification
        uint256 pseudorandom = uint256(keccak256(abi.encode(publicKeyG1, publicKeyG2, signature, block.timestamp, block.prevrandao)));
        G1Point memory sigTester = mul(G1(), pseudorandom);

        // pairing to verify signature
        // e([sk * H]_1, -[1]_2) + e([H]_1, [sk]_2) == 0
        valid = pairing(signature, negG2(), mul(G1(), sigHash), publicKeyG2);
        require(valid, "Invalid signature");

        // Another way to verify signature by adding some random in verification
        // e([random * sk * H]_1, -[1]_2) + e([random * H]_1, [sk]_2) == 0
        valid = pairing(mul(signature, pseudorandom), negG2(), mul(mul(G1(), pseudorandom), sigHash), publicKeyG2);
        require(valid, "Invalid signature");
    }
}
