package com.beidouht.tls;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.exception.ContextedRuntimeException;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class JcePKCS12Utils {
    private static final Provider BOUNCYCASTLE_PROVIDER = new BouncyCastleProvider();
    public static P12Result gen(String appId,InputStream introIs) {
        Security.addProvider(BOUNCYCASTLE_PROVIDER);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(outputStream);
        P12Result p12Result = new P12Result();
        try {
            char[] keyPassword = appId.toCharArray();
            KeyStore credentials = JcaUtils.createCredentials(keyPassword);
            //使用appId导入12的密码
            PrivateKey key = (PrivateKey) credentials.getKey(JcaUtils.END_ENTITY_ALIAS, keyPassword);
            // 写证书部分
            zip(zip,"client_key.pem",key);

            // 写入说明书
            //ClassPathResource resource = new ClassPathResource("证书使用说明.txt");
            zip.putNextEntry(new ZipEntry("证书使用说明.txt"));
            IOUtils.copy(introIs, zip);
            introIs.close();
            zip.closeEntry();
            // 写秘钥部分
            Certificate certificate = credentials.getCertificate(JcaUtils.END_ENTITY_ALIAS);
            zip(zip,"client_cert.pem",certificate);

            StringWriter sw = new StringWriter();
            JcaPEMWriter publicKeyWriter = new JcaPEMWriter(sw);
            publicKeyWriter.writeObject(certificate.getPublicKey());
            publicKeyWriter.close();
            p12Result.setPublicKey(sw.toString());

            // 生成p12
            zip.putNextEntry(new ZipEntry("client.p12"));
            Certificate[] chain = credentials.getCertificateChain(JcaUtils.END_ENTITY_ALIAS);
            PKCS12PfxPdu pfx = createPKCS12File(key, chain, keyPassword);
            // make sure we don't include indefinite length encoding
            byte[] p12Bytes = pfx.getEncoded(ASN1Encoding.DER);
            p12Result.setP12(p12Bytes);
            zip.write(p12Bytes);
            zip.closeEntry();
            zip.close();
        } catch (Exception e) {
            throw new ContextedRuntimeException("证书生成或压缩错误", e)
                    .addContextValue("appId", appId);
        }
        IOUtils.closeQuietly(outputStream);
        p12Result.setZipData(outputStream.toByteArray());
        return p12Result;
    }


    public static byte[] readPkcs12(byte[] bytes,String appId,InputStream introIs) throws Exception {
        Security.addProvider(BOUNCYCASTLE_PROVIDER);
        //
        // first do a "blow by blow" read of the PKCS#12 file.
        //
        char[] charPassword = appId.toCharArray();
        //
        // or alternately just load it up using a KeyStore
        //
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");

        pkcs12Store.load(new ByteArrayInputStream(bytes), charPassword);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(outputStream);
        for (Enumeration en = pkcs12Store.aliases(); en.hasMoreElements(); ) {
            String alias = (String) en.nextElement();

            if (pkcs12Store.isCertificateEntry(alias)) {
                //zip(zip,"client_cert.pem",certificate);
                X509Certificate certificate = (X509Certificate) pkcs12Store.getCertificate(alias);
                if (certificate.getSubjectDN().toString().equals("CN=Location CA Certificate")) {
                    zip(zip, "client_cert.pem", certificate);
                }
            } else if (pkcs12Store.isKeyEntry(alias)) {
                // 写证书部分
                zip(zip,"client_key.pem",pkcs12Store.getKey(alias,charPassword));
            }
        }
        zip.putNextEntry(new ZipEntry("证书使用说明.txt"));
        IOUtils.copy(introIs, zip);
        introIs.close();
        zip.closeEntry();
        zip.putNextEntry(new ZipEntry("client.p12"));
        zip.write(bytes);
        zip.closeEntry();
        zip.close();
        return outputStream.toByteArray();
    }

    private static void createPKCS12File(OutputStream pfxOut, PrivateKey key, Certificate[] chain,char[] keyPassword)
            throws Exception {
        PKCS12PfxPdu pfx = createPKCS12File(key,chain,keyPassword);

        // make sure we don't include indefinite length encoding
        pfxOut.write(pfx.getEncoded(ASN1Encoding.DER));

        pfxOut.close();
    }

    private static void createPKCS12File(OutputStream pfxOut, PKCS12PfxPdu pfx)
            throws Exception {
        // make sure we don't include indefinite length encoding
        pfxOut.write(pfx.getEncoded(ASN1Encoding.DER));

        pfxOut.close();
    }

    private static PKCS12PfxPdu createPKCS12File(PrivateKey key, Certificate[] chain,char[] keyPassword)
            throws Exception {
        OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").build(keyPassword);

        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate) chain[2]);

        taCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate) chain[1]);

        caCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Intermediate Certificate"));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate) chain[0]);

        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Location's Key"));
        SubjectKeyIdentifier pubKeyId = extUtils.createSubjectKeyIdentifier(chain[0].getPublicKey());
        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(key, encOut);

        keyBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Location's Key"));
        keyBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();

        builder.addData(keyBagBuilder.build());

        builder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC).setProvider("BC").build(keyPassword), new PKCS12SafeBag[]{eeCertBagBuilder.build(), caCertBagBuilder.build(), taCertBagBuilder.build()});

        return builder.build(new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256), keyPassword);
    }

    private static PKCS12PfxPdu readPKCS12File(byte[] pfxBytes,char[] password)
            throws Exception {
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxBytes);

        if (!pfx.isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE), password)) {
            System.err.println("PKCS#12 MAC test failed!");
        }

        ContentInfo[] infos = pfx.getContentInfos();

        Map certMap = new HashMap();
        Map certKeyIds = new HashMap();
        Map privKeyMap = new HashMap();
        Map privKeyIds = new HashMap();

        InputDecryptorProvider inputDecryptorProvider = new  JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider("BC").build(password);
        JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter().setProvider("BC");

        for (int i = 0; i != infos.length; i++) {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                for (int b = 0; b != bags.length; b++) {
                    PKCS12SafeBag bag = bags[b];

                    X509CertificateHolder certHldr = (X509CertificateHolder) bag.getBagValue();
                    X509Certificate cert = jcaConverter.getCertificate(certHldr);

                    Attribute[] attributes = bag.getAttributes();
                    for (int a = 0; a != attributes.length; a++) {
                        Attribute attr = attributes[a];

                        if (attr.getAttrType().equals(PKCS12SafeBag.friendlyNameAttribute)) {
                            certMap.put(((DERBMPString) attr.getAttributeValues()[0]).getString(), cert);
                        } else if (attr.getAttrType().equals(PKCS12SafeBag.localKeyIdAttribute)) {
                            certKeyIds.put(attr.getAttributeValues()[0], cert);
                        }
                    }
                }
            } else {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);

                KeyFactory keyFact = KeyFactory.getInstance(info.getPrivateKeyAlgorithm().getAlgorithm().getId(), "BC");
                PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));

                Attribute[] attributes = bags[0].getAttributes();
                for (int a = 0; a != attributes.length; a++) {
                    Attribute attr = attributes[a];

                    if (attr.getAttrType().equals(PKCS12SafeBag.friendlyNameAttribute)) {
                        privKeyMap.put(((DERBMPString) attr.getAttributeValues()[0]).getString(), privKey);
                    } else if (attr.getAttrType().equals(PKCS12SafeBag.localKeyIdAttribute)) {
                        privKeyIds.put(privKey, attr.getAttributeValues()[0]);
                    }
                }
            }
        }

        System.out.println("########## PFX Dump");
        for (Iterator it = privKeyMap.keySet().iterator(); it.hasNext(); ) {
            String alias = (String) it.next();
            System.out.println("Key Entry: " + alias + ", Subject: " + (((X509Certificate) certKeyIds.get(privKeyIds.get(privKeyMap.get(alias)))).getSubjectDN()));
        }
        for (Iterator it = certMap.keySet().iterator(); it.hasNext(); ) {
            String alias = (String) it.next();
            System.out.println("Certificate Entry: " + alias + ", Subject: " + (((X509Certificate) certMap.get(alias)).getSubjectDN()));
        }
        return pfx;
    }

    public static void zip(ZipOutputStream zip,String fileName,Object obj){
        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter keyWriter = new JcaPEMWriter(sw);
            zip.putNextEntry(new ZipEntry(fileName));
            keyWriter.writeObject(obj);
            IOUtils.closeQuietly(keyWriter);
            IOUtils.closeQuietly(sw);
            IOUtils.write(sw.toString(), zip, "UTF-8" );
            zip.closeEntry();
        }catch (Exception e){
            throw new RuntimeException("zip 错误", e);
        }
    }

}