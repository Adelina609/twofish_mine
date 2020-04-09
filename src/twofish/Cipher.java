package twofish;

public interface Cipher {

    void init(boolean forEncryption, byte[] key,
              byte[] IV);

    int processBlock(byte[] in, int inOff, byte[] out, int outOff);

    void reset();
}