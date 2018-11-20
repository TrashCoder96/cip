package ru.hc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;


public class Cip {

    static KeyFactory kf;

    public static void main(String[] args) throws Exception {
        File dataFile = new File("/rsa/data.json");
        String token = generateTokenForUser(FileUtils.readFileToString(dataFile));
        System.out.println("token = " + token);
    }

    public static String generateTokenForUser(String jsonBody) throws Exception {
        kf = KeyFactory.getInstance("RSA");
        JWSAlgorithm alg = JWSAlgorithm.RS256;
        JWSHeader header = new JWSHeader.Builder(alg)
                .type(JOSEObjectType.JWT)
                .build();
        Payload contentPayload = new Payload(jsonBody);
        JWSObject encjwsObject = new JWSObject(header, contentPayload);
        encjwsObject.sign(getSigner());
        String token = encjwsObject.serialize();
        //JWSObject jwsObject = JWSObject.parse("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdWlkIjoiMTIzNDUiLCJzY29wZSI6WyJhY2Nlc3MiXSwiZXhwIjoxNDg0ODE1MTg5LCJqdGkiOiI2YTY4NTVhYS0xMzk5LTRlNmYtYTRlYS03NWQ4MmQ0ZWM4MzMiLCJjbGllbnRfaWQiOiJpYnMifQ.aYHPz6QZzQ5P4xESg9VeAWnmNpC7aDKZcO9He8E9JPXY9FvBIIQmfrXzNrRghqXS5nF9uim0LTWsH1Qkq8Z7LV5zReioRcSJfUJdjwz-KKm6JvHWdplv7i3qt1QjF2_YRnTKbDfDO5NfYBM4Wy7iTF2Wt2pMxeG_YxCIUudy3AmN_JxWF9roCIpTv0qTlrgLlyqFS7CwmWVdu7jFw4JagB48iW49xpsbZPvei6C6vbJPfPH49w9bPZgGNuMxfx2DAyA5RWcnCe1dMKyesUPKEtRnk0mz3ffqXuKJS0Z52CD9WcELZ6nFGgOzV3c-bgC5ffo_ZGhNtH9jBrIGP23sMg");
        JWSObject jwsObject = JWSObject.parse(token);
        File filePubK = new File("/rsa/publickey");
        byte[] encodedKey = Base64.decode(FileUtils.readFileToString(filePubK));
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
        PublicKey publicKey = kf.generatePublic(pubKeySpec);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
        final boolean verify = jwsObject.verify(verifier);
        return token;
    }

    public static RSASSASigner getSigner() throws Exception {
        File filePrK = new File("/rsa/privatekey");
        File filePubK = new File("/rsa/publickey");
        if (!filePrK.exists() || !filePubK.exists()) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = kf.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

            // generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
            PublicKey pubKey = kf.generatePublic(publicKeySpec);
            PrivateKey prKey = kf.generatePrivate(privateKeySpec);

            //Base64.decode()
            System.out.println("Private key = " + javax.xml.bind.DatatypeConverter.printBase64Binary(prKey.getEncoded()));
            System.out.println("Public key = " + javax.xml.bind.DatatypeConverter.printBase64Binary(pubKey.getEncoded()));

            writeToFile(filePrK.getPath(), javax.xml.bind.DatatypeConverter.printBase64Binary(prKey.getEncoded()).getBytes());
            writeToFile(filePubK.getPath(), javax.xml.bind.DatatypeConverter.printBase64Binary(pubKey.getEncoded()).getBytes());
            RSASSASigner signer = new RSASSASigner(prKey);
            return signer;
        } else {
            byte[] encodedKey = Base64.decode(FileUtils.readFileToString(filePrK));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            PrivateKey prKey = kf.generatePrivate(pkcs8EncodedKeySpec);
            RSASSASigner signer = new RSASSASigner(prKey);
            return signer;
        }
    }

    public static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    private static byte[] getBytesFromFile(String path) {
        byte[] getBytes = {};
        try {
            File file = new File(path);
            getBytes = new byte[(int) file.length()];
            InputStream is = new FileInputStream(file);
            is.read(getBytes);
            is.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return getBytes;
    }

}