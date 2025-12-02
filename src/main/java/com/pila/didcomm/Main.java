package com.pila.didcomm;

import com.pila.credential.vc.JSONCredential;
import com.pila.didcomm.ecdh.Secp256k1;

import java.security.MessageDigest;

public class Main {
    public static void main(String[] args) {
        String message = "{\n" +
                " \"@context\": [\"...\"],\n" +
                " \"id\": \"urn:uuid:...\",\n" +
                " \"type\": [\"VerifiableCredential\"],\n" +
                " \"issuer\": \"did:example:123456\",\n" +
                " \"issuanceDate\": \"...\",\n" +
                " \"credentialSubject\": { \"...\": \"...\" },\n" +
                " \"proof\": {\n" +
                " \"type\": \"Ed25519Signature2020\",\n" +
                " \"created\": \"...\",\n" +
                " \"verificationMethod\": \"did:example:123456#key-1\",\n" +
                " \"proofPurpose\": \"assertionMethod\",\n" +
                " \"jws\": \"...\"\n" +
                " }\n" +
                "}";

        // Sample keys (secp256k1): compressed public key and raw 32-byte private key
        // in
        // hex
        String senderPublicKeyHex = "039c2283702214062a04efb6707db8308ff566c38f93adb93193b175d4f9b354b7";
        String senderPrivateKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";

        try {
            byte[] sharedSecret = Secp256k1.deriveSharedSecret(senderPublicKeyHex,
                    senderPrivateKeyHex);
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

        testCredential();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static void testCredential() {
        // try to parse credential
        String rawCredential = "{"
                + "\"validFrom\":\"2025-12-01T02:25:20Z\","
                + "\"id\":\"urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0\","
                + "\"validUntil\":\"2025-12-02T02:25:20Z\","
                + "\"@context\":["
                + "\"https://www.w3.org/ns/credentials/v2\""

                + "],"
                + "\"type\":\"VerifiableCredential\","
                + "\"credentialSubject\":{"
                + "\"issuer\":\"did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e\","
                + "\"citizenIdentify\":\"024537894514\","
                + "\"result\":\"matched\","
                + "\"id\":\"did:nda:testnet:0x86977f96a4f0973819d204541b1d9d48424302d9\","
                + "\"issuedBy\":\"Mobifone\","
                + "\"issuedDate\":\"2025-12-01\","
                + "\"phoneNumber\":\"0761804353\""
                + "},"
                + "\"proof\":{"
                + "\"proofPurpose\":\"assertionMethod\","
                + "\"created\":\"2025-12-01T02:25:21Z\","
                + "\"proofValue\":\"a7a970560732bf2e2cb4a02b4a566e12adc658e57aac871f1399c2d4532f2d0037186ae3173990a3d98dec31e518e03efb1e7ea438d919babc9974356def26d000\","
                + "\"type\":\"DataIntegrityProof\","
                + "\"cryptosuite\":\"ecdsa-rdfc-2019\","
                + "\"verificationMethod\":\"did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e#key-1\""
                + "},"
                + "\"issuer\":\"did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e\""
                + "}";

        try {
            JSONCredential credential = JSONCredential.parseJSONCredential(rawCredential.getBytes());

            // print string of credential contents
            byte[] credentialContents = credential.getContents();
            System.out.println(new String(credentialContents));

            // verify credential
            credential.verify();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
