package twofish;

public class TwofishWrapper {

    public static PCBCCipher cipher;

    public TwofishWrapper(byte[] key, boolean forEncryption, byte[] IV) {

        final TwofishEngine tfe = new TwofishEngine();
        cipher = new PCBCCipher(tfe);
        cipher.init(forEncryption, key, IV);

    }

    public byte[] processPCBC(byte[] input) {

        final byte[] out = new byte[input.length];

        cipher.processBlock(input, 0, out, 0);

        return out;

    }

    public static byte[] processECB(byte[] key, boolean forEncryption, byte[] input) {

        final ECBCipher cipher = new ECBCipher(new TwofishEngine());
        cipher.init(forEncryption, key);
        final byte[] out = new byte[input.length];

        final int len1 = cipher.processBytes(input, 0, input.length, out, 0);

        cipher.doFinal(out, len1);
        return out;
    }
}
