package com.pila.didcomm;

import com.pila.didcomm.crypto.AesGcm;
import com.pila.didcomm.jwe.JweBuilder;

public final class Encryptor {
    private Encryptor() {}

    public static String encrypt(byte[] key, String plaintext) {
        AesGcm.Result res = AesGcm.encrypt(key, plaintext.getBytes());
        return JweBuilder.build(slice16(key), res.nonce, res.ciphertext);
    }

    private static byte[] slice16(byte[] in) {
        byte[] out = new byte[16];
        System.arraycopy(in, 0, out, 0, Math.min(16, in.length));
        return out;
    }
}


