package twofish;

public class TwofishWrapper {

    static CBCBlockCipher cipher;

    public TwofishWrapper(byte[] key, boolean forEncryption, byte[] IV) {

        final TwofishEngine tfe = new TwofishEngine();
        cipher = new CBCBlockCipher(tfe);
        final KeyParameter kp = new KeyParameter(key);
        final ParametersWithIV piv = new ParametersWithIV(kp, IV);
        cipher.init(forEncryption, piv);

    }


    //TODO убрать сбс полностью из проекта?
    public static byte[] processCBC(byte[] input) {

        final byte[] out = new byte[input.length];

        cipher.processBlock(input, 0, out, 0);

        return out;

    }

    public static byte[] processECB(byte[] key, boolean forEncryption, byte[] input) {

        final BufferedBlockCipher cipher = new BufferedBlockCipher(new TwofishEngine());
        final KeyParameter kp = new KeyParameter(key);
        cipher.init(forEncryption, kp);
        final byte[] out = new byte[input.length];

        final int len1 = cipher.processBytes(input, 0, input.length, out, 0);

        try {
            cipher.doFinal(out, len1);
        } catch (final CryptoException e) {
            throw new RuntimeException(e);
        }
        return out;
    }
}