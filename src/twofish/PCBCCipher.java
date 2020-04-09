package twofish;

import java.util.Arrays;

public class PCBCCipher
        implements Cipher {
    private byte[] IV;
    private byte[] pcbcV;
    private byte[] pcbcNextV;

    private static final int blockSize = 16;  // bytes = 128 bits

    private Cipher cipher = null;
    private boolean encrypting;

    public PCBCCipher(
            Cipher cipher) {
        this.cipher = cipher;

        this.IV = new byte[blockSize];
        this.pcbcV = new byte[blockSize];
        this.pcbcNextV = new byte[blockSize];
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

        for (int i = 0; i < blockSize; i++) {
            pcbcV[i] ^= in[inOff + i];
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
