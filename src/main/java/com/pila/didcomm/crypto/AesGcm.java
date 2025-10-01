package com.pila.didcomm.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public final class AesGcm {
    private AesGcm() {}

    public static class Result {
        public final byte[] nonce;
        public final byte[] ciphertext;

        public Result(byte[] nonce, byte[] ciphertext) {
            this.nonce = nonce;
            this.ciphertext = ciphertext;
        }
    }

    public static Result encrypt(byte[] key, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            int nonceLen = 12;
            byte[] nonce = new byte[nonceLen];
            new SecureRandom().nextBytes(nonce);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new Result(nonce, ciphertext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


