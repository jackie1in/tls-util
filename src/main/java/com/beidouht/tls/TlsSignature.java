package com.beidouht.tls;

import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.CharArrayReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class TlsSignature {
    public static class GenTLSSignatureResult {
        public String errMessage;
        public String urlSig;
        public int expireTime;
        public int initTime;

        public GenTLSSignatureResult() {
            errMessage = "";
            urlSig = "";
        }
    }

    public static class CheckTLSSignatureResult {
        public String errMessage;
        public boolean verifyResult;
        public int expireTime;
        public int initTime;

        public CheckTLSSignatureResult() {
            errMessage = "";
            verifyResult = false;
        }
    }

    /**
     * 生成 tls 票据
     *
     * @param expire  有效期，单位是秒，推荐一个月
     * @param app_id  应用的 app_id
     * @param privStr 生成 tls 票据使用的私钥内容
     * @return 如果出错，GenTLSSignatureResult 中的 urlSig为空，errMsg 为出错信息，成功返回有效的票据
     */
    public static GenTLSSignatureResult GenTLSSignature(long expire,
                                                        long app_id,
                                                        String privStr) {
        GenTLSSignatureResult result = new GenTLSSignatureResult();

        Security.addProvider(new BouncyCastleProvider());
        Reader reader = new CharArrayReader(privStr.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PEMParser parser = new PEMParser(reader);
        PrivateKey privKeyStruct;
        try {
            Object obj = parser.readObject();
            parser.close();
            privKeyStruct = converter.getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());
        } catch (IOException e) {
            result.errMessage = "read pem error:" + e.getMessage();
            return result;
        }

        //Create Json string and serialization String
        String jsonString = "{"
                + "\"TLS.app_id\":\"" + app_id + "\","
                + "\"TLS.expire_after\":\"" + expire + "\""
                + "}";
        //System.out.println("#jsonString : \n" + jsonString);

        String time = String.valueOf(System.currentTimeMillis() / 1000);
        String SerialString =
                "TLS.app_id:" + app_id + "\n" +
                        "TLS.time:" + time + "\n" +
                        "TLS.expire_after:" + expire + "\n";


        //System.out.println("#SerialString : \n" + SerialString);
        //System.out.println("#SerialString Hex: \n" + Hex.encodeHexString(SerialString.getBytes()));

        try {
            //Create Signature by SerialString
            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(privKeyStruct);
            signature.update(SerialString.getBytes(Charset.forName("UTF-8")));
            byte[] signatureBytes = signature.sign();

            String sigTLS = Base64.toBase64String(signatureBytes);
            //System.out.println("#sigTLS : " + sigTLS);

            //Add TlsSig to jsonString
            JSONObject jsonObject = JSONObject.parseObject(jsonString);
            jsonObject.put("TLS.sign", sigTLS);
            jsonObject.put("TLS.time", time);
            jsonString = jsonObject.toString();

            // System.out.println("#jsonString : \n" + jsonString);

            //compression
            Deflater compresser = new Deflater();
            compresser.setInput(jsonString.getBytes(Charset.forName("UTF-8")));

            compresser.finish();
            byte[] compressBytes = new byte[512];
            int compressBytesLength = compresser.deflate(compressBytes);
            compresser.end();

            result.urlSig = new String(Base64Util.base64EncodeUrl(Arrays.copyOfRange(compressBytes, 0, compressBytesLength)));
        } catch (Exception e) {
            e.printStackTrace();
            result.errMessage = e.getMessage();
        }

        return result;
    }

    /**
     * 生成 tls 票据，精简参数列表，有效期默认为 180 天
     *
     * @param app_id  应用的 app_id
     * @param privStr 私钥文件内容
     * @return GenTLSSignatureResult
     */
    public static GenTLSSignatureResult GenTLSSignatureEx(
            long app_id,
            String privStr) {
        return GenTLSSignatureEx(app_id, privStr, 3600 * 24 * 180);
    }

    /**
     * 生成 tls 票据，精简参数列表
     *
     * @param app_id  应用的 app_id
     * @param privStr 私钥文件内容
     * @param expire  有效期，以秒为单位，推荐时长一个月
     * @return GenTLSSignatureResult
     */
    public static GenTLSSignatureResult GenTLSSignatureEx(
            long app_id,
            String privStr,
            long expire) {
        return GenTLSSignature(expire, app_id, privStr);
    }

    public static CheckTLSSignatureResult CheckTLSSignatureEx(
            String urlSig,
            long app_id,
            String publicKey) throws DataFormatException {

        CheckTLSSignatureResult result = new CheckTLSSignatureResult();
        Security.addProvider(new BouncyCastleProvider());

        byte[] compressBytes = Base64Util.base64DecodeUrl(urlSig.getBytes(Charset.forName("UTF-8")));

        //Decompression
        Inflater decompression = new Inflater();
        decompression.setInput(compressBytes, 0, compressBytes.length);
        byte[] decompressBytes = new byte[1024];
        int decompressLength = decompression.inflate(decompressBytes);
        decompression.end();

        String jsonString = new String(Arrays.copyOfRange(decompressBytes, 0, decompressLength));

        //Get TLS.sign from json
        JSONObject jsonObject = JSONObject.parseObject(jsonString);
        String sigTLS = jsonObject.getString("TLS.sign");

        //debase64 TLS.sign to get serailString
        byte[] signatureBytes = Base64.decode(sigTLS.getBytes(Charset.forName("UTF-8")));

        try {
            String strapp_id = jsonObject.getString("TLS.app_id");
            String sigTime = jsonObject.getString("TLS.time");
            String sigExpire = jsonObject.getString("TLS.expire_after");

            if (!Long.valueOf(strapp_id).equals(app_id)) {
                result.errMessage = "app_id "
                        + strapp_id
                        + " in tls sig not equal app_id "
                        + app_id
                        + " in request";
                return result;
            }

            if (System.currentTimeMillis() / 1000 - Long.parseLong(sigTime) > Long.parseLong(sigExpire)) {
                result.errMessage = "TLS sig is out of date";
                return result;
            }

            //Get Serial String from json
            String SerialString =
                    "TLS.app_id:" + app_id + "\n" +
                            "TLS.time:" + sigTime + "\n" +
                            "TLS.expire_after:" + sigExpire + "\n";

            Reader reader = new CharArrayReader(publicKey.toCharArray());
            PEMParser parser = new PEMParser(reader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Object obj = parser.readObject();
            parser.close();
            PublicKey pubKeyStruct = converter.getPublicKey((SubjectPublicKeyInfo) obj);

            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initVerify(pubKeyStruct);
            signature.update(SerialString.getBytes(Charset.forName("UTF-8")));
            boolean bool = signature.verify(signatureBytes);
            result.expireTime = Integer.parseInt(sigExpire);
            result.initTime = Integer.parseInt(sigTime);
            result.verifyResult = bool;
        } catch (Exception e) {
            e.printStackTrace();
            result.errMessage = "Failed in checking sig";
        }

        return result;
    }

    public static GenTLSSignatureResult genSig(
            long app_id,
            String priKey) {
        // 默认 180 天
        return GenTLSSignature(24 * 3600 * 180, app_id, priKey);
    }

    public static GenTLSSignatureResult genSig(
            long app_id,
            int expire,
            String priKey) {
        return GenTLSSignature(expire, app_id, priKey);
    }
}
