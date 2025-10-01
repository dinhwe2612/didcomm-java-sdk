package com.pila.didcomm;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public final class Decryptor {
    private Decryptor() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    public static String decrypt(String jweStr, byte[] sharedKey) {
        try {
            Map<?,?> jwe = MAPPER.readValue(jweStr, Map.class);
            byte[] iv = URL_DECODER.decode((String) jwe.get("iv"));
            byte[] ciphertext = URL_DECODER.decode((String) jwe.get("ciphertext"));

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(sharedKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


