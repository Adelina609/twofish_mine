package twofish;

public class ECBMode {
    private byte[] buf = new byte[blockSize];

    private int bufOff;

    private Cipher cipher;

    private static int blockSize = 16;  // bytes = 128 bits


    public ECBMode(
            Cipher cipher) {
        this.cipher = cipher;

        bufOff = 0;
    }

    public void init(
            boolean isEncryption,
            byte[] key)
            throws IllegalArgumentException {

        reset();

        cipher.init(isEncryption, key, null);
    }

    public int processBytes(
            byte[] in,
            int inOff,
            int len,
            byte[] out,
            int outOff) {

        int blockSize = this.getBlockSize();

        int resultLen = 0;
        int intervalLenBuf = buf.length - bufOff;

        if (len > intervalLenBuf) {
            System.arraycopy(in, inOff, buf, bufOff, intervalLenBuf);

            resultLen += cipher.processBlock(buf, 0, out, outOff);

            bufOff = 0;
            len -= intervalLenBuf;
            inOff += intervalLenBuf;

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

    public int getBlockSize() {
        return blockSize;
    }
}
