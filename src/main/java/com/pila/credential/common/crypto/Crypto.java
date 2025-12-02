package com.pila.credential.common.crypto;

import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Cryptographic operations for credential signing and verification.
 * Note: This is a placeholder. Full implementation requires secp256k1 library.
 */
public class Crypto {
    
    /**
     * Signs data using ECDSA with secp256k1.
     * @param signData The data to sign
     * @param privKeyHex The private key in hex format
     * @return The signature bytes (65 bytes: r, s, v)
     */
    public static byte[] ecdsaSign(byte[] signData, String privKeyHex) throws Exception {
        // TODO: Implement using BouncyCastle or similar secp256k1 library
        throw new UnsupportedOperationException(
            "ECDSA signing not yet implemented. Requires secp256k1 library."
        );
    }
    
    public static boolean ecdsaVerifySignature(String publicKeyHex,
        String signatureHex,
        byte[] message) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1. secp256k1 curve params
        var params = ECNamedCurveTable.getParameterSpec("secp256k1");

        // 2. Public key: hex -> ECPoint -> PublicKey
        byte[] pubKeyBytes = Hex.decode(publicKeyHex);  // typically 04 || X || Y
        ECPoint point = params.getCurve().decodePoint(pubKeyBytes);

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        PublicKey publicKey = kf.generatePublic(
            new org.bouncycastle.jce.spec.ECPublicKeySpec(point, params)
        );

        // 3. Decode signature hex
        byte[] sigBytes = Hex.decode(signatureHex);

        // Debug (optional)
        // System.out.printf("sig len = %d, first byte = 0x%02x%n", sigBytes.length, sigBytes[0]);

        // 4. Normalize to DER format for BC
        byte[] derSig = toDerEcdsaSignature(sigBytes);

        // 5. Verify
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(derSig);
    }

    /**
    * Convert common ECDSA signature encodings to DER:
    * - If already DER (starts with 0x30), return as is
    * - If 64 bytes: raw r||s
    * - If 65 bytes: Ethereum v||r||s
    */
    private static byte[] toDerEcdsaSignature(byte[] sigBytes) throws Exception {
        // Case A: already DER (SEQUENCE tag)
        if (sigBytes.length > 0 && (sigBytes[0] & 0xFF) == 0x30) {
            return sigBytes;
        }

        byte[] rBytes;
        byte[] sBytes;

        if (sigBytes.length == 64) {
            // Case B: raw r||s
            rBytes = Arrays.copyOfRange(sigBytes, 0, 32);
            sBytes = Arrays.copyOfRange(sigBytes, 32, 64);

        } else if (sigBytes.length == 65) {
            // Case C: Ethereum v||r||s
            // v is sigBytes[0], we ignore it for ECDSA verify
            rBytes = Arrays.copyOfRange(sigBytes, 1, 33);
            sBytes = Arrays.copyOfRange(sigBytes, 33, 65);

        } else {
            throw new IllegalArgumentException(
            "Unsupported ECDSA signature format: length=" + sigBytes.length
            );
        }

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));

        return new DERSequence(v).getEncoded(); // proper DER signature
    }
    
    
    /**
     * Verifies a JWT proof.
     * @param req The request map containing the proof
     * @param publicKeyHex The public key in hex format
     * @return true if JWT proof is valid
     */
    public static boolean verifyJwtProof(Map<String, Object> req, String publicKeyHex) throws Exception {
        // TODO: Implement JWT proof verification
        throw new UnsupportedOperationException(
            "JWT proof verification not yet implemented."
        );
    }
    
    /**
     * Verifies a JSON signature.
     * @param publicKeyBytes The public key bytes
     * @param message The message bytes
     * @param signatureBytes The signature bytes
     * @return true if signature is valid
     */
    public static boolean verifyJSONSignature(byte[] publicKeyBytes, byte[] message, byte[] signatureBytes) {
        // TODO: Implement JSON signature verification
        throw new UnsupportedOperationException(
            "JSON signature verification not yet implemented."
        );
    }
    
    /**
     * Converts a key string to bytes.
     * @param keyHex The key in hex format (with or without 0x prefix)
     * @return The key bytes
     */
    public static byte[] keyToBytes(String keyHex) throws Exception {
        if (keyHex == null || keyHex.isEmpty()) {
            throw new IllegalArgumentException("key is not in hex format");
        }
        
        String hex = keyHex.startsWith("0x") ? keyHex.substring(2) : keyHex;
        
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length");
        }
        
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}

