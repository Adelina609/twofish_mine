package twofish;

public class ECBCipher {
    protected byte[] buf;
    protected int bufOff;

    protected boolean isEncryption;
    protected Cipher cipher;

    protected boolean partialBlockOkay;
    protected boolean pgpCFB;
    private static int blockSize = 16;  // bytes = 128 bits


    public ECBCipher(
            Cipher cipher) {
        this.cipher = cipher;

        buf = new byte[blockSize];
        bufOff = 0;
    }

    public void init(
            boolean isEncryption,
            byte[] key)
            throws IllegalArgumentException {
        this.isEncryption = isEncryption;

        reset();

        cipher.init(isEncryption, key, null);
    }

    public int getBlockSize() {
        return blockSize;
    }

    //какой размер необходим для дополнения блока буфера
    public int getUpdateOutputSize(
            int len) {
        int total = len + bufOff;
        int leftOver;

        if (pgpCFB) {
            if (isEncryption) {
                leftOver = total % buf.length - (blockSize + 2);
            } else {
                leftOver = total % buf.length;
            }
        } else {
            leftOver = total % buf.length;
        }

        return total - leftOver;
    }

    public int processBytes(
            byte[] in,
            int inOff,
            int len,
            byte[] out,
            int outOff) {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int blockSize = this.getBlockSize();

        int resultLen = 0;
        int gapLen = buf.length - bufOff;

        if (len > gapLen) {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            resultLen += cipher.processBlock(buf, 0, out, outOff);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > buf.length) {
                resultLen += cipher.processBlock(in, inOff, out, outOff + resultLen);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;

        if (bufOff == buf.length) {
            resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen);
            bufOff = 0;
        }

        return resultLen;
    }

    //последний блок данных, обработка
    public int doFinal(
            byte[] out,
            int outOff) {
        try {
            int resultLen = 0;

            if (bufOff != 0) {
                cipher.processBlock(buf, 0, buf, 0);
                resultLen = bufOff;
                bufOff = 0;
                System.arraycopy(buf, 0, out, outOff, resultLen);
            }

            return resultLen;
        } finally {
            reset();
        }
    }

    public void reset() {

        for (int i = 0; i < buf.length; i++) {
            buf[i] = 0;
        }

        bufOff = 0;

        cipher.reset();
    }
}
