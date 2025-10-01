package com.pila.didcomm;

import com.pila.didcomm.ecdh.Secp256k1;

import java.security.MessageDigest;

public class Main {
    public static void main(String[] args) {
        String message = "{\n" +
                "    \"@context\": [\"...\"],\n" +
                "    \"id\": \"urn:uuid:...\",\n" +
                "    \"type\": [\"VerifiableCredential\"],\n" +
                "    \"issuer\": \"did:example:123456\",\n" +
                "    \"issuanceDate\": \"...\",\n" +
                "    \"credentialSubject\": { \"...\": \"...\" },\n" +
                "    \"proof\": {\n" +
                "        \"type\": \"Ed25519Signature2020\",\n" +
                "        \"created\": \"...\",\n" +
                "        \"verificationMethod\": \"did:example:123456#key-1\",\n" +
                "        \"proofPurpose\": \"assertionMethod\",\n" +
                "        \"jws\": \"...\"\n" +
                "    }\n" +
                "}";

        // Sample keys (secp256k1): compressed public key and raw 32-byte private key in hex
        String senderPublicKeyHex = "039c2283702214062a04efb6707db8308ff566c38f93adb93193b175d4f9b354b7";
        String senderPrivateKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";

        try {
            byte[] sharedSecret = Secp256k1.deriveSharedSecret(senderPublicKeyHex, senderPrivateKeyHex);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            System.out.printf("Recipient derived: %s\n", bytesToHex(digest));

            String jweOutput = Encryptor.encrypt(sharedSecret, message);
            System.out.printf("JWE Output: %s\n", jweOutput);

            String plaintext = Decryptor.decrypt(jweOutput, sharedSecret);
            System.out.printf("Plaintext: %s\n", plaintext);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}


