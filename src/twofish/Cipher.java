package twofish;

import twofish.exceptions.DataLengthException;

public interface Cipher {

    void init(boolean forEncryption, byte[] key,
              byte[] IV)
            throws IllegalArgumentException;

    int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException;

    void reset();
}