package twofish;

public class TwofishWrapper {

    public static PCBCCipherMode cipher;

    public TwofishWrapper(byte[] key, boolean isEncryption, byte[] IV) {

        cipher = new PCBCCipherMode(new TwofishImplCipher());
        cipher.init(isEncryption, key, IV);

    }

    public byte[] processPCBC(byte[] input) {

        final byte[] out = new byte[input.length];

        cipher.processBlock(input, 0, out, 0);

        return out;

    }

    public static byte[] processECB(byte[] key, boolean isEncryption, byte[] input) {

        final ECBMode cipher = new ECBMode(new TwofishImplCipher());
        cipher.init(isEncryption, key);
        final byte[] out = new byte[input.length];

        final int len1 = cipher.processBytes(input, 0, input.length, out, 0);

        cipher.doFinal(out, len1);
        return out;
    }
}
