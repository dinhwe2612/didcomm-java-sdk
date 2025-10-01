package com.pila.didcomm.ecdh;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public final class Secp256k1 {
    private Secp256k1() {}

    private static final ECParameterSpec CURVE_SPEC = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(
            CURVE_SPEC.getCurve(), CURVE_SPEC.getG(), CURVE_SPEC.getN(), CURVE_SPEC.getH());

    public static byte[] deriveSharedSecret(String senderPubHex, String receiverPrivHex) {
        byte[] pubBytes = hexToBytes(senderPubHex);
        byte[] privBytes = hexToBytes(receiverPrivHex);

        ECPoint q = CURVE_SPEC.getCurve().decodePoint(pubBytes);
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(q, DOMAIN);

        BigInteger d = new BigInteger(1, privBytes);
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(d, DOMAIN);

        BasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privParams);
        BigInteger shared = agreement.calculateAgreement(pubParams);
        return bigIntegerTo32(shared);
    }

    private static byte[] bigIntegerTo32(BigInteger v) {
        byte[] bytes = v.toByteArray();
        if (bytes.length == 32) return bytes;
        if (bytes.length == 33 && bytes[0] == 0) {
            byte[] out = new byte[32];
            System.arraycopy(bytes, 1, out, 0, 32);
            return out;
        }
        byte[] out = new byte[32];
        int start = Math.max(0, bytes.length - 32);
        int len = bytes.length - start;
        System.arraycopy(bytes, start, out, 32 - len, len);
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}


