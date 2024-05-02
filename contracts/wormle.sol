// SPDX-License-Identifier: MIT
// Adapted from Alt-BN128 code from: https://github.com/HarryR/solcrypto/tree/master
pragma solidity ^0.8.25;

contract Wormle {
    // p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 internal constant FIELD_ORDER =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 internal constant GEN_ORDER =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 internal constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 internal constant CURVE_A =
        0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

    // Point on the Alt-BN128 curve
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    // Cipher point (kG, P_m + k P_k)
    struct EncryptedMessage {
        G1Point x;
        G1Point y;
    }

    struct HandCard {
        EncryptedMessage id;
        EncryptedMessage k;
    }
    EncryptedMessage[6] public hand;

    function drawCard(uint8 id, uint256 k, uint256 k2, G1Point memory publicKey) private returns (bool, HandCard memory) {
    
        // Shift k right by 8 bits
        uint256 shiftedData = k >> 8;

        // Convert id to uint256 and shift it left by (256 - 8) bits
        // 256 total bits in a uint256, and shifting id left by (256 - 8 = 248) bits
        uint256 idShifted = uint256(id) << 248;

        // Combine shiftedData with idShifted using bitwise OR to place id in the front
        shiftedData = shiftedData | idShifted;

        //shift to the right 10 bits so encoding works without loss of data
        shiftedData = shiftedData >> 10;

        //shifted so that it can be encrypted
        uint256 shiftedK = k >> 10;

        bool success1;
        bool success2;

        EncryptedMessage memory card;
        EncryptedMessage memory kVal;



        //encrypt shiftedData with shiftedk 
        (success1, card) = encrypt(shiftedData, publicKey, shiftedK);

        //encrypt the k value with k2, used for validation
        (success2, kVal) = encrypt(shiftedK, publicKey, k2);

        HandCard memory handCard = HandCard(card, kVal);

        if(!success1 && !success2) {
            return (false, handCard);
        }

        
        return (true, handCard);
    }

    //return true or false for success, updates state of hand remembering only the encrypted id, returns the encrypted HandCard array (id and k)
    function drawHand(G1Point memory publicKey) public returns (bool, HandCard[6] memory) {
        HandCard[6] memory pushToPlayerHand;
        bool successLoop;
        for (uint8 i = 0; i < 6; i++) {
            HandCard memory handCard;
            bool success;
            //Dummy k values for now
            (success, handCard) = drawCard(i, uint256(123 + i), uint256(234 + i), publicKey);
            hand[i] = handCard.id;
            pushToPlayerHand[i] = handCard;
            if(!success) {
                successLoop = false;
            }
        }
        if(!successLoop) {
            return (false, pushToPlayerHand);
        }
        return (true, pushToPlayerHand);  
    }

    function viewHand() public view returns (EncryptedMessage[6] memory) {
        return hand;
    }

    function validateCard(uint8 index, uint256 data, uint256 k) public returns (bool) {
        //no need to shift data since it is already shifted to be encoded correctly
        //need to shift k though since it is encoded
        uint256 shiftedK = k >> 10;

        EncryptedMessage memory cardId;

        bool success;
        (success, cardId) = encrypt(data, G(), shiftedK);

        if(!success) {
            return false;
        }
        if(cardId.x.x == hand[index].x.x && cardId.x.y == hand[index].x.y && cardId.y.x == hand[index].y.x && cardId.y.y == hand[index].y.y) {
            return true;
        } else {
            return false;
        }
    }

    function useCard(uint8 index, uint256 data, uint256 k) public returns (bool, uint8) {
        if(validateCard(index, data, k)) {
            hand[index] = EncryptedMessage(G1Point(0, 0), G1Point(0, 0));
            return (true, getId(data));
        } else {
            return (false, 0);
        }
    }

    function getId(uint256 encoded) public view returns (uint8) {
        return uint8(encoded >> 248);
    }

    function G() private pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    // Converts a uint256 to a point on the Alt-BN128 Curve
    // Should be less than 2^243 as 10 bits will be used for finding a curve point which needs to be less than the field modulo
    // For simplicity, input data should start with 2 empty bytes followed by 30 data bytes
    // Uses Koblitz's method, roughly 2^-1024 chance of failure
    function encodeUint256(
        uint256 input
    ) private returns (bool, G1Point memory) {
        uint256 xStart = input << 10;

        uint256 beta;
        uint256 y;

        for (uint256 i = 0; i < 1024; i++) {
            uint256 x = xStart + i;

            (beta, y) = computeCurveY(x);
            if (beta == mulmod(y, y, FIELD_ORDER)) {
                return (true, G1Point(x, y));
            }
        }

        return (false, G1Point(0, 0));
    }

    function encrypt(
        uint256 data,
        G1Point memory publicKey,
        uint256 k
    ) private returns (bool, EncryptedMessage memory) {
        G1Point memory encodedData;
        bool success;

        (success, encodedData) = encodeUint256(data);

        if (!success) {
            // If the encoding fails
            return (false, EncryptedMessage(G1Point(0, 0), G1Point(0, 0)));
        } else {

            // k is a random number
            // G is the generator point
            // P_m is the encoded message
            // P_k is the public key
            // n_k is the private key

            // kG
            G1Point memory cipherX = g1mul(G(), k);

            // P_m + k P_k = P_m + k n_k G
            G1Point memory cipherY = g1add(encodedData, g1mul(publicKey, k));

            return (true, EncryptedMessage(cipherX, cipherY));
        }
    }

    /**
     * Given X, find Y
     *
     *   where y = sqrt(x^3 + b)
     *
     * Returns: (x^3 + b), y
     */
    function computeCurveY(uint256 x) internal returns (uint256, uint256) {
        // beta = (x^3 + b) % p
        uint256 beta = addmod(
            mulmod(mulmod(x, x, FIELD_ORDER), x, FIELD_ORDER),
            CURVE_B,
            FIELD_ORDER
        );

        // y^2 = x^3 + b
        // this acts like: y = sqrt(beta)
        uint256 y = expMod(beta, CURVE_A, FIELD_ORDER);

        return (beta, y);
    }

    // a - b = c;
    function submod(uint a, uint b) internal pure returns (uint) {
        uint a_nn;

        if (a > b) {
            a_nn = a;
        } else {
            a_nn = a + GEN_ORDER;
        }

        return addmod(a_nn - b, 0, GEN_ORDER);
    }

    function expMod(
        uint256 _base,
        uint256 _exponent,
        uint256 _modulus
    ) internal returns (uint256 retval) {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20; // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20; // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20; // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                5,
                input,
                0xc0,
                output,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
        return output[0];
    }

    // Point addition on the elliptic curve
    function g1add(
        G1Point memory p1,
        G1Point memory p2
    ) internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
    }

    // scalar multiplication on elliptic curve
    function g1mul(
        G1Point memory p,
        uint256 s
    ) internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
    }
}
