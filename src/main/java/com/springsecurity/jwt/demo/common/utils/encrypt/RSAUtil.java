package com.springsecurity.jwt.demo.common.utils.encrypt;

import lombok.Data;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * RSA使用X509EncodedKeySpec、PKCS8EncodedKeySpec生成公钥和私钥
 * 加密数据大小不能超过127 bytes
 * 加签、验签、加密、解密、生成公钥、私钥
 */
public class RSAUtil {

    private static final String PATH = "/home/eric/IdeaProjects/keys";

    public static void main(String[] args) throws Exception {
        //生成公私钥文件
        RSAUtil.generateKeysToFile(PATH);

        String publicKey = RSAUtil.readKeyFromFile(PATH + "/publicKey.keystore");
        String privateKey = RSAUtil.readKeyFromFile(PATH + "/privateKey.keystore");
        System.out.println("publicKey：" + publicKey);
        System.out.println("privateKey：" + privateKey);

        System.out.println("---------------------------------------------");

        String sign = RSAUtil.signByPrivateKey("测试加签", privateKey);
        System.out.println("generateToken：" + sign);
        System.out.println("验签：" + RSAUtil.verifySignByPublicKey("测试加签", publicKey, sign));

        System.out.println("---------------------------------------------");

        String cipherText = RSAUtil.encryptByPublicKey("测试加密明文数据", RSAUtil.readPublicKeyFromString(publicKey));
        System.out.println("cipherText：" + cipherText);
        String plainText = RSAUtil.decryptByPrivateKey(cipherText, RSAUtil.readPrivateKeyFromString(privateKey));
        System.out.println("plainText：" + plainText);
    }

    /**
     * 生成字符串类型的公钥、私钥对
     *
     * @return RsaKeyPair
     */
    public static RsaKeyPair generateKeys() {
        // 默认长度1024
        return generateKeys(1024);
    }


    /**
     * 生成字符串类型的公钥、私钥对
     *
     * @return RsaKeyPair
     */
    public static RsaKeyPair generateKeys(int keyLength) {
        RsaKeyPair keys = new RsaKeyPair();
        KeyPair keyPair = generateRSAKeyPair(keyLength);
        if (keyPair != null) {

            String publicKeyString = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded()), StandardCharsets.UTF_8);
            String privateKeyString = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()), StandardCharsets.UTF_8);
            keys.setPublicKey(publicKeyString);
            keys.setPrivateKey(privateKeyString);
        }
        return keys;
    }


    /**
     * 生成RSA密钥对(默认密钥长度为1024)
     *
     * @return
     */
    public static KeyPair generateRSAKeyPair() {
        return generateRSAKeyPair(1024);
    }

    /**
     * 生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 生成公私钥对
     *
     * @param dirPath 生成文件路径文件夹
     */
    public static void generateKeysToFile(String dirPath) {
        RsaKeyPair keyPair = generateKeys();
        try {
            Files.write(Paths.get(dirPath + "/publicKey.keystore"), keyPair.getPublicKey().getBytes());
            Files.write(Paths.get(dirPath + "/privateKey.keystore"), keyPair.getPrivateKey().getBytes());
            /*
            BufferedWriter publicbw = new BufferedWriter(new FileWriter(new File(dirPath+"/publicKey.keystore")));
            BufferedWriter privatebw = new BufferedWriter(new FileWriter(new File(dirPath+"/privateKey.keystore")));
            publicbw.write(keyPair.getPublicKey());
            privatebw.write(keyPair.getPrivateKey());
            publicbw.flush();
            publicbw.close();
            privatebw.flush();
            privatebw.close();
            */
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从文件中读取公钥或私钥
     *
     * @param filePath 文件路径
     * @return 公钥或私钥
     */
    public static String readKeyFromFile(String filePath) {
        try {
            return Files.lines(Paths.get(filePath)).collect(Collectors.joining());
            /*BufferedReader br = new BufferedReader(new FileReader(new File(filePath)));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while((readLine = br.readLine()) != null)
            {
              sb.append(readLine);
            }
            br.close();
            return sb.toString();
            */
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字符串中加载公钥
     *
     * @return 公钥
     */
    public static RSAPublicKey readPublicKeyFromString(String publicKeyStr) {
        try {
            byte[] bt = Base64.getDecoder().decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bt);
            return (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字符串中加载私钥
     *
     * @return 私钥
     */
    public static RSAPrivateKey readPrivateKeyFromString(String privateKeyStr) {
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 私钥加签
     *
     * @param content    报文
     * @param privateKey 私钥
     * @return 签名值
     */
    public static String signByPrivateKey(String content, String privateKey) {
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            //MD5withRSA
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(priKey);
            signature.update(content.getBytes());
            byte[] sign = signature.sign();
            return new String(Base64.getEncoder().encode(sign), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥验签
     *
     * @param content   报文
     * @param publicKey 公钥
     * @param sign      签名值
     * @return 验签是否通过
     */
    public static boolean verifySignByPublicKey(String content, String publicKey, String sign) {
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
            //MD5withRSA
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(pubKey);
            signature.update(content.getBytes());
            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 公钥加密
     *
     * @param plainText 明文
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception
     */
    public static String encryptByPublicKey(String plainText, RSAPublicKey publicKey) throws Exception {
        if (publicKey == null) {
            throw new Exception("公钥为空！");
        }
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output = cipher.doFinal(plainText.getBytes());
            return new String(Base64.getEncoder().encode(output), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 私钥解密
     *
     * @param cipherText 密文
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception
     */
    public static String decryptByPrivateKey(String cipherText, RSAPrivateKey privateKey) throws Exception {
        if (privateKey == null) {
            throw new Exception("私钥为空！");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] output = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(output);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * rsq公私密钥对
     */
    @Data
    public static class RsaKeyPair {
        private String privateKey;

        private String publicKey;
    }
}
