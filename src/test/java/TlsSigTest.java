import com.beidouht.tls.TlsSignature;
import org.junit.Assert;
import org.junit.Test;

public class TlsSigTest {
    @Test
    public void genAndVerify() {
        try {
            // Use pemfile keys to test
            String privStr = "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEpAIBAAKCAQEAunswSQ8UY+IzAzuL0F/IhD3vW7SUBbbj46CI+YdxCI4o9Y00\n" +
                    "U0q4jfTP57lP8MFhSSu83/AzTJCRxNYkdk3ya2rjIt/V/7vBrWj/waZl+XzT+qhM\n" +
                    "8pbq4rXJLU5PmiqbKtCyuhdJGh/A7UkQCjinTTTcZRa8okFlARzMuSJ9KJBEsw6O\n" +
                    "mZ7BAI9cmsmJGwZJJZBzRiT141jq+PCJTgcG2o6DdWf28V3sW08F5JWHyOzoqFwK\n" +
                    "OtkTtPM2gPUF2BDFFBiS/yKa//LdeoFAakqeyPc0rhW6Jhx0Wz44BlptWAE5I2K4\n" +
                    "9ql6JdOxLDpLXfU/1QsZyXKIHo2Piy7jskljCQIDAQABAoIBAAZva3WNK6r2vcPs\n" +
                    "ZIeThpvpqnG26mGRs8BbMRIYKaWd7xPqN4mlGBFUbW6vTaIe4974JdOkhy13n7aN\n" +
                    "nULn4oG9qPDyWhqYV1ET2oX+pzsHPIyqpva7XO4atkKPlt4L5Y1PGAI/MEQ47E0Q\n" +
                    "xGW8TSm0G7CK94XlGjmbmmtl7hb3Z5rbxzv5CEuONTVY/HC7xtP0VsoqI8Dcmvzd\n" +
                    "zHkF+9wYQQaI04Ncrk98R7RN/19ZPmiVjNJwsQrf44+ar5HX/vwaKTj8FrTrbXIT\n" +
                    "hn5E2VVuNM8B3XRoBhcVsR7q+ayTYrH7SWhfDHBH/zuFk+27vksKM/pMaDe+Khcu\n" +
                    "zoLdgPECgYEA8HoyLqdj/XzEgVnuuzc9lF29dKZmjgiQp8pf3DkWW/yk9U/W8FsW\n" +
                    "j25qLADDMxgW22e+zn5J3n7APPaaHlMXV4thpHlhGIhZQIVA4XI08fFrjLgztmo0\n" +
                    "a8jN3WuPZ7ZlaZHwRAVv8w7pN4TU3mWpWkHxEvf5GCDFGeo/HsDoLDMCgYEAxoS5\n" +
                    "uhO0cJcRrMIZuA1qN00gG9yVE5HvZj3HrDgRtfNzna2kiPcmqg9IjcHaEIgEN5tD\n" +
                    "yV3B+jf+z5SDv28b7R2MZuBvOtB3BmAWYR7ThjBAVQ42FpWGUDYwCU63NsNbPJ+H\n" +
                    "znMeuOFZMFvIAxkdWSuhm9DMAsO9NEa7ghraN9MCgYB6KNkNMiNtRdBdFV5c5Hb3\n" +
                    "w5bWhyFZzagOVJPVv3pISFNT+rbpapxPSHvO1qRSdE5ILq+THjxQNntZfLxV40fc\n" +
                    "RQXZE3/rgng0eny3Cdkzfrxvw7MhW1o91sgdTuKOgO2Lb4NqSojQJCb8+RFZ2LLr\n" +
                    "EsxwIl/7jcoSnBhsevp2WQKBgQCDTwVefGws0PAC+nxyjoUEQUKMy1HcGPpmAVVS\n" +
                    "p9+nH3oJAPNFGV18vRE7ms63gpBvi4bB6f9Fl8Y23cBrXn31UEcvQSKxn3QrRmFn\n" +
                    "KjG1n7Ldz8GdHJgz9DO/5E4xrfRqXAdDWkgm9/+7ien5iqIr+j0ySGC5L2m161dZ\n" +
                    "zpMquwKBgQC9y1ERD89i4LS/3eJGJgNfiRVyfib+KZ6HpJs8zrj+XL6LXTfZTCFj\n" +
                    "GuMgwMjDEI5TDICxsqfWo8sxl0HBzy5/hL1HB96JipwUg7j42FiGaMF7E6uOCpnV\n" +
                    "FoLpI5F9t8Ue9ut4nC7aTPyNImnvRj19wkDhv3pkP1+ZNhD9DCwgIQ==\n" +
                    "-----END RSA PRIVATE KEY-----\n";

            // change public pem string to public string
            String pubStr = "-----BEGIN PUBLIC KEY-----\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunswSQ8UY+IzAzuL0F/I\n" +
                    "hD3vW7SUBbbj46CI+YdxCI4o9Y00U0q4jfTP57lP8MFhSSu83/AzTJCRxNYkdk3y\n" +
                    "a2rjIt/V/7vBrWj/waZl+XzT+qhM8pbq4rXJLU5PmiqbKtCyuhdJGh/A7UkQCjin\n" +
                    "TTTcZRa8okFlARzMuSJ9KJBEsw6OmZ7BAI9cmsmJGwZJJZBzRiT141jq+PCJTgcG\n" +
                    "2o6DdWf28V3sW08F5JWHyOzoqFwKOtkTtPM2gPUF2BDFFBiS/yKa//LdeoFAakqe\n" +
                    "yPc0rhW6Jhx0Wz44BlptWAE5I2K49ql6JdOxLDpLXfU/1QsZyXKIHo2Piy7jsklj\n" +
                    "CQIDAQAB\n" +
                    "-----END PUBLIC KEY-----";
            // generate signature
            TlsSignature.GenTLSSignatureResult result = TlsSignature.GenTLSSignatureEx(67855501114736708L, privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            TlsSignature.CheckTLSSignatureResult checkResult = TlsSignature.CheckTLSSignatureEx(result.urlSig, 67855501114736708L, pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = TlsSignature.CheckTLSSignatureEx(result.urlSig, 6785550111473670L, pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);


            // new interface generate signature
            result = TlsSignature.genSig(67855501114736708L, privStr);
            Assert.assertNotEquals(null, result);
            Assert.assertNotEquals(null, result.urlSig);
            Assert.assertNotEquals(0, result.urlSig.length());

            // check signature
            checkResult = TlsSignature.CheckTLSSignatureEx(result.urlSig, 67855501114736708L, pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertTrue(checkResult.verifyResult);

            checkResult = TlsSignature.CheckTLSSignatureEx(result.urlSig, 6785550111473670L, pubStr);
            Assert.assertNotEquals(null, checkResult);
            Assert.assertFalse( checkResult.verifyResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
