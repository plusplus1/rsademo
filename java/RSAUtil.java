
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class RSAUtil {

    private static final String ALG_CRYPTO = "RSA/ECB/PKCS1Padding";
    private static final String ALG_SIGN = "SHA1withRSA";
    private static final String ALG_KEY = "RSA";

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }


    public static int getKeyBits(Key k) {
        RSAKey rk = (RSAKey) k;
        return rk.getModulus().bitLength();
    }


    public static PublicKey loadRSAPublicKey(String strPk) throws Exception {

        PemReader pr = new PemReader(new StringReader(strPk));
        PemObject po = pr.readPemObject();
        pr.close();

        PublicKey pubKey = KeyFactory.getInstance(ALG_KEY).generatePublic(new X509EncodedKeySpec(
                po.getContent()
        ));

        return pubKey;
    }


    public static PrivateKey loadRSAPrivateKey(String strPk) throws Exception {

        PemReader pr = new PemReader(new StringReader(strPk));
        PemObject po = pr.readPemObject();
        pr.close();

        return KeyFactory.getInstance(ALG_KEY).generatePrivate(new PKCS8EncodedKeySpec(
                po.getContent()
        ));
    }


    public static String rsaEncrypt(String text, Key keyObj) throws Exception {
        Cipher cipher = Cipher.getInstance(ALG_CRYPTO, new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, keyObj);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ByteArrayInputStream bis = new ByteArrayInputStream(text.getBytes("UTF-8"));

        int enSize = getKeyBits(keyObj) / 8 - 28;
        byte[] inputBuffer = new byte[enSize];


        int len;
        while (true) {
            len = bis.read(inputBuffer);
            if (len < 0) {
                break;
            }

            byte[] buf = cipher.doFinal(inputBuffer, 0, len);
            bos.write(buf);
        }
        return Base64.encodeBase64String(bos.toByteArray());
    }


    public static String rsaDecrypt(String text, Key keyObj) throws Exception {

        byte[] srcBytes = Base64.decodeBase64(text);
        Cipher cipher = Cipher.getInstance(ALG_CRYPTO, new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, keyObj);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int deSize = getKeyBits(keyObj) / 8;

        for (int i = 0; i < srcBytes.length; i += deSize) {
            byte[] buf = cipher.doFinal(srcBytes, i, deSize);
            bos.write(buf);
        }
        return new String(bos.toByteArray());
    }


    public static String signature(int appId, String bizParams, PrivateKey partnerPrivateKey) throws Exception {
        Signature s = Signature.getInstance(ALG_SIGN);
        s.initSign(partnerPrivateKey);
        s.update(String.format("%d %s", appId, bizParams).getBytes("UTF-8"));
        return Base64.encodeBase64String(s.sign());
    }


    public static boolean verify(int appId, String bizParams, String sign, PublicKey partnerPublicKey) throws Exception {
        Signature s = Signature.getInstance(ALG_SIGN);
        s.initVerify(partnerPublicKey);
        s.update(String.format("%d %s", appId, bizParams).getBytes("UTF-8"));

        return s.verify(Base64.decodeBase64(sign));
    }


}
