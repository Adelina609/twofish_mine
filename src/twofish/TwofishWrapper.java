package twofish;

public class TwofishWrapper {

    public static PCBCCipher cipher;

    public TwofishWrapper(byte[] key, boolean isEncryption, byte[] IV) {

        final TwofishEngine tfe = new TwofishEngine();
        cipher = new PCBCCipher(tfe);
        cipher.init(isEncryption, key, IV);

    }

    public byte[] processPCBC(byte[] input) {

        final byte[] out = new byte[input.length];

        cipher.processBlock(input, 0, out, 0);

        return out;

    }

    public static byte[] processECB(byte[] key, boolean isEncryption, byte[] input) {

        final ECBCipher cipher = new ECBCipher(new TwofishEngine());
        cipher.init(isEncryption, key);
        final byte[] out = new byte[input.length];

        final int len1 = cipher.processBytes(input, 0, input.length, out, 0);

        cipher.doFinal(out, len1);
        return out;
    }
}
