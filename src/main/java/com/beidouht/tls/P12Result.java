package com.beidouht.tls;

import java.util.Arrays;
import java.util.Objects;

/**
 * @author <a href="mailto:hilin2333@gmail.com">created by silencecorner 2019/2/19 2:10 PM</a>
 */
public class P12Result {
    private byte[] zipData;
    // p12二级制文件
    private byte[] p12;
    private String publicKey;

    public byte[] getZipData() {
        return zipData;
    }

    public void setZipData(byte[] zipData) {
        this.zipData = zipData;
    }

    public byte[] getP12() {
        return p12;
    }

    public void setP12(byte[] p12) {
        this.p12 = p12;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        P12Result p12Result = (P12Result) o;
        return Arrays.equals(zipData, p12Result.zipData) &&
                Arrays.equals(p12, p12Result.p12) &&
                Objects.equals(publicKey, p12Result.publicKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(publicKey);
        result = 31 * result + Arrays.hashCode(zipData);
        result = 31 * result + Arrays.hashCode(p12);
        return result;
    }
}
