package twofish;

import java.util.Arrays;

public class PCBCCipherMode
        implements Cipher {

    private static final int blockSize = 16;  //128 бит
    private byte[] IV = new byte[blockSize];
    private byte[] pcbcV = new byte[blockSize];
    private byte[] pcbcNextV = new byte[blockSize];


    private Cipher cipher = null;
    private boolean encrypting;

    public PCBCCipherMode(
            Cipher cipher) {
        this.cipher = cipher;
    }

    public void init(
            boolean encrypting,
            byte[] key,
            byte[] IV)
            throws IllegalArgumentException {
        this.encrypting = encrypting;

        this.IV = IV;

        reset();

        cipher.init(encrypting, key, IV);
    }


    public int processBlock(
            byte[] in,
            int inOff,
            byte[] out,
            int outOff) {
        return (encrypting) ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    public void reset() {
        System.arraycopy(IV, 0, pcbcV, 0, IV.length);
        Arrays.fill(pcbcNextV, (byte) 0);

        cipher.reset();
    }

    private int encryptBlock(
            byte[] in,
            int inOff,
            byte[] out,
            int outOff) {

        int mod = in.length % blockSize;
        int additionalLength =  mod != 0 ? blockSize - mod : 0;

        byte padding = 0;
        if (mod != 0) {
            padding = (byte) (blockSize - mod);
        }

        for (int i = 0; i < blockSize + additionalLength; i++) {
            pcbcV[i] ^= in[inOff + i];

            if (i > in.length){
                pcbcV[i % blockSize] = padding;
            }
        }

        int length = cipher.processBlock(pcbcV, 0, out, outOff);

        System.arraycopy(out, outOff, pcbcV, 0, pcbcV.length);

        return length;
    }

    private int decryptBlock(
            byte[] in,
            int inOff,
            byte[] out,
            int outOff) {

        System.arraycopy(in, inOff, pcbcNextV, 0, blockSize);

        int length = cipher.processBlock(in, inOff, out, outOff);

        for (int i = 0; i < blockSize; i++) {
            out[outOff + i] ^= pcbcV[i];
        }

        //бэкап буфера в след позицию
        byte[] tmp;

        tmp = pcbcV;
        pcbcV = pcbcNextV;
        pcbcNextV = tmp;

        return length;
    }
}
