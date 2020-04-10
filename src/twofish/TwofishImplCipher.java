package twofish;

public final class TwofishImplCipher
        implements Cipher {
    //конечное поле
    private static final int GF256_FDBK = 0x169;
    private static final int GF256_FDBK_2 = GF256_FDBK / 2;
    private static final int GF256_FDBK_4 = GF256_FDBK / 4;

    //генератор поля
    private static final int RS_GF_FDBK = 0x14D;

    private static final int ROUNDS = 16;
    private static final int MAX_ROUNDS = 16;
    private static final int BLOCK_SIZE = 16;  // 128 бит
    private static final int MAX_KEY_BITS = 256;

    private static final int INPUT_WHITEN = 0;
    private static final int OUTPUT_WHITEN = INPUT_WHITEN + BLOCK_SIZE / 4; // 4
    private static final int ROUND_SUBKEYS = OUTPUT_WHITEN + BLOCK_SIZE / 4;// 8

    private static final int TOTAL_SUBKEYS = ROUND_SUBKEYS + 2 * MAX_ROUNDS;// 40

    private static final int SK_STEP = 0x02020202;
    private static final int SK_BUMP = 0x01010101;
    private static final int SK_ROTL = 9;

    private boolean encrypting = false;

    private int[] gMDS0 = new int[MAX_KEY_BITS];
    private int[] gMDS1 = new int[MAX_KEY_BITS];
    private int[] gMDS2 = new int[MAX_KEY_BITS];
    private int[] gMDS3 = new int[MAX_KEY_BITS];

    private int[] gSubKeys;
    private int[] gSBox;

    //подстановки
    private static final int P_00 = 1;
    private static final int P_01 = 0;
    private static final int P_02 = 0;
    private static final int P_03 = P_01 ^ 1;
    private static final int P_04 = 1;

    private static final int P_10 = 0;
    private static final int P_11 = 0;
    private static final int P_12 = 1;
    private static final int P_13 = P_11 ^ 1;
    private static final int P_14 = 0;

    private static final int P_20 = 1;
    private static final int P_21 = 1;
    private static final int P_22 = 0;
    private static final int P_23 = P_21 ^ 1;
    private static final int P_24 = 0;

    private static final int P_30 = 0;
    private static final int P_31 = 1;
    private static final int P_32 = 1;
    private static final int P_33 = P_31 ^ 1;
    private static final int P_34 = 1;

    //k64 - количество 8 байтовых блоков
    private int k64Cnt = 0;

    private byte[] workingKey = null;

    public TwofishImplCipher() {
        //MDS матрица
        int[] m1 = new int[2];
        int[] mX = new int[2];
        int[] mY = new int[2];
        int j;

        for (int i = 0; i < MAX_KEY_BITS; i++) {
            j = PermutationBoxes.P[0][i] & 0xff;
            m1[0] = j;
            mX[0] = Mx_X(j) & 0xff;
            mY[0] = Mx_Y(j) & 0xff;

            j = PermutationBoxes.P[1][i] & 0xff;
            m1[1] = j;
            mX[1] = Mx_X(j) & 0xff;
            mY[1] = Mx_Y(j) & 0xff;

            gMDS0[i] = m1[P_00] | mX[P_00] << 8 |
                    mY[P_00] << 16 | mY[P_00] << 24;

            gMDS1[i] = mY[P_10] | mY[P_10] << 8 |
                    mX[P_10] << 16 | m1[P_10] << 24;

            gMDS2[i] = mX[P_20] | mY[P_20] << 8 |
                    m1[P_20] << 16 | mY[P_20] << 24;

            gMDS3[i] = mX[P_30] | m1[P_30] << 8 |
                    mY[P_30] << 16 | mX[P_30] << 24;
        }
    }

    public void init(
            boolean encrypting,
            byte[] key,
            byte[] IV) {
        this.encrypting = encrypting;
        this.workingKey = key;
        this.k64Cnt = (this.workingKey.length / 8);
        setKey(this.workingKey);
    }

    public int processBlock(
            byte[] in,
            int inOff,
            byte[] out,
            int outOff) {

        if (encrypting) {
            encryptBlock(in, inOff, out, outOff);
        } else {
            decryptBlock(in, inOff, out, outOff);
        }

        return BLOCK_SIZE;
    }

    public void reset() {
        if (this.workingKey != null) {
            setKey(this.workingKey);
        }
    }

    private void setKey(byte[] key) {
        int[] k32e = new int[MAX_KEY_BITS / 64]; // 4
        int[] k32o = new int[MAX_KEY_BITS / 64]; // 4

        int[] sBoxKeys = new int[MAX_KEY_BITS / 64]; // 4
        gSubKeys = new int[TOTAL_SUBKEYS];

        if (k64Cnt < 1) {
            throw new IllegalArgumentException("Размер ключа меньше 64 бит");
        }

        if (k64Cnt > 4) {
            throw new IllegalArgumentException("Размер ключа больше 256 бит");
        }

        for (int i = 0; i < k64Cnt; i++) {
            int p = i * 8;

            k32e[i] = BytesTo32Bits(key, p);
            k32o[i] = BytesTo32Bits(key, p + 4);

            //определяем раундовые подключи
            sBoxKeys[k64Cnt - 1 - i] = RS_MDS_Encode(k32e[i], k32o[i]);
        }

        int q, A, B;
        for (int i = 0; i < TOTAL_SUBKEYS / 2; i++) {
            q = i * SK_STEP;
            A = F32(q, k32e);
            B = F32(q + SK_BUMP, k32o);
            B = B << 8 | B >>> 24;
            A += B;
            gSubKeys[i * 2] = A;
            A += B;
            gSubKeys[i * 2 + 1] = A << SK_ROTL | A >>> (32 - SK_ROTL);
        }

        int k0 = sBoxKeys[0];
        int k1 = sBoxKeys[1];
        int k2 = sBoxKeys[2];
        int k3 = sBoxKeys[3];
        int b0, b1, b2, b3;

        gSBox = new int[4 * MAX_KEY_BITS];
        for (int i = 0; i < MAX_KEY_BITS; i++) {
            b0 = b1 = b2 = b3 = i;
            switch (k64Cnt & 3) {
                case 1:
                    gSBox[i * 2] = gMDS0[(PermutationBoxes.P[P_01][b0] & 0xff) ^ b0(k0)];
                    gSBox[i * 2 + 1] = gMDS1[(PermutationBoxes.P[P_11][b1] & 0xff) ^ b1(k0)];
                    gSBox[i * 2 + 0x200] = gMDS2[(PermutationBoxes.P[P_21][b2] & 0xff) ^ b2(k0)];
                    gSBox[i * 2 + 0x201] = gMDS3[(PermutationBoxes.P[P_31][b3] & 0xff) ^ b3(k0)];
                    break;
                case 0: // 256 битовый ключ
                    b0 = (PermutationBoxes.P[P_04][b0] & 0xff) ^ b0(k3);
                    b1 = (PermutationBoxes.P[P_14][b1] & 0xff) ^ b1(k3);
                    b2 = (PermutationBoxes.P[P_24][b2] & 0xff) ^ b2(k3);
                    b3 = (PermutationBoxes.P[P_34][b3] & 0xff) ^ b3(k3);
                case 3: // 192 бит ключ
                    b0 = (PermutationBoxes.P[P_03][b0] & 0xff) ^ b0(k2);
                    b1 = (PermutationBoxes.P[P_13][b1] & 0xff) ^ b1(k2);
                    b2 = (PermutationBoxes.P[P_23][b2] & 0xff) ^ b2(k2);
                    b3 = (PermutationBoxes.P[P_33][b3] & 0xff) ^ b3(k2);
                case 2: // 128 бит ключ
                    gSBox[i * 2] = gMDS0[(PermutationBoxes.P[P_01]
                            [(PermutationBoxes.P[P_02][b0] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)];
                    gSBox[i * 2 + 1] = gMDS1[(PermutationBoxes.P[P_11]
                            [(PermutationBoxes.P[P_12][b1] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)];
                    gSBox[i * 2 + 0x200] = gMDS2[(PermutationBoxes.P[P_21]
                            [(PermutationBoxes.P[P_22][b2] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)];
                    gSBox[i * 2 + 0x201] = gMDS3[(PermutationBoxes.P[P_31]
                            [(PermutationBoxes.P[P_32][b3] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
                    break;
            }
        }
    }

    private void encryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex) {
        //входное забеливание
        int x0 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[INPUT_WHITEN];
        int x1 = BytesTo32Bits(src, srcIndex + 4) ^ gSubKeys[INPUT_WHITEN + 1];
        int x2 = BytesTo32Bits(src, srcIndex + 8) ^ gSubKeys[INPUT_WHITEN + 2];
        int x3 = BytesTo32Bits(src, srcIndex + 12) ^ gSubKeys[INPUT_WHITEN + 3];

        int k = ROUND_SUBKEYS;
        int t0, t1;
        for (int r = 0; r < ROUNDS; r += 2) {
            t0 = Fe32_0(x0);
            t1 = Fe32_3(x1);
            x2 ^= t0 + t1 + gSubKeys[k++];
            x2 = x2 >>> 1 | x2 << 31;
            x3 = (x3 << 1 | x3 >>> 31) ^ (t0 + 2 * t1 + gSubKeys[k++]);

            t0 = Fe32_0(x2);
            t1 = Fe32_3(x3);
            x0 ^= t0 + t1 + gSubKeys[k++];
            x0 = x0 >>> 1 | x0 << 31;
            x1 = (x1 << 1 | x1 >>> 31) ^ (t0 + 2 * t1 + gSubKeys[k++]);
        }

        //выходное забеливание
        Bits32ToBytes(x2 ^ gSubKeys[OUTPUT_WHITEN], dst, dstIndex);
        Bits32ToBytes(x3 ^ gSubKeys[OUTPUT_WHITEN + 1], dst, dstIndex + 4);
        Bits32ToBytes(x0 ^ gSubKeys[OUTPUT_WHITEN + 2], dst, dstIndex + 8);
        Bits32ToBytes(x1 ^ gSubKeys[OUTPUT_WHITEN + 3], dst, dstIndex + 12);
    }

    private void decryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex) {
        int x2 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[OUTPUT_WHITEN];
        int x3 = BytesTo32Bits(src, srcIndex + 4) ^ gSubKeys[OUTPUT_WHITEN + 1];
        int x0 = BytesTo32Bits(src, srcIndex + 8) ^ gSubKeys[OUTPUT_WHITEN + 2];
        int x1 = BytesTo32Bits(src, srcIndex + 12) ^ gSubKeys[OUTPUT_WHITEN + 3];

        int k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
        int t0, t1;
        for (int r = 0; r < ROUNDS; r += 2) {
            t0 = Fe32_0(x2);
            t1 = Fe32_3(x3);
            x1 ^= t0 + 2 * t1 + gSubKeys[k--];
            x0 = (x0 << 1 | x0 >>> 31) ^ (t0 + t1 + gSubKeys[k--]);
            x1 = x1 >>> 1 | x1 << 31;

            t0 = Fe32_0(x0);
            t1 = Fe32_3(x1);
            x3 ^= t0 + 2 * t1 + gSubKeys[k--];
            x2 = (x2 << 1 | x2 >>> 31) ^ (t0 + t1 + gSubKeys[k--]);
            x3 = x3 >>> 1 | x3 << 31;
        }

        Bits32ToBytes(x0 ^ gSubKeys[INPUT_WHITEN], dst, dstIndex);
        Bits32ToBytes(x1 ^ gSubKeys[INPUT_WHITEN + 1], dst, dstIndex + 4);
        Bits32ToBytes(x2 ^ gSubKeys[INPUT_WHITEN + 2], dst, dstIndex + 8);
        Bits32ToBytes(x3 ^ gSubKeys[INPUT_WHITEN + 3], dst, dstIndex + 12);
    }

    //для сабкейс
    private int F32(int x, int[] k32) {
        int b0 = b0(x);
        int b1 = b1(x);
        int b2 = b2(x);
        int b3 = b3(x);
        int k0 = k32[0];
        int k1 = k32[1];
        int k2 = k32[2];
        int k3 = k32[3];

        int result = 0;
        switch (k64Cnt & 3) {
            case 1:
                result = gMDS0[(PermutationBoxes.P[P_01][b0] & 0xff) ^ b0(k0)] ^
                        gMDS1[(PermutationBoxes.P[P_11][b1] & 0xff) ^ b1(k0)] ^
                        gMDS2[(PermutationBoxes.P[P_21][b2] & 0xff) ^ b2(k0)] ^
                        gMDS3[(PermutationBoxes.P[P_31][b3] & 0xff) ^ b3(k0)];
                break;
            case 0: /* 256 bits of key */
                b0 = (PermutationBoxes.P[P_04][b0] & 0xff) ^ b0(k3);
                b1 = (PermutationBoxes.P[P_14][b1] & 0xff) ^ b1(k3);
                b2 = (PermutationBoxes.P[P_24][b2] & 0xff) ^ b2(k3);
                b3 = (PermutationBoxes.P[P_34][b3] & 0xff) ^ b3(k3);
            case 3:
                b0 = (PermutationBoxes.P[P_03][b0] & 0xff) ^ b0(k2);
                b1 = (PermutationBoxes.P[P_13][b1] & 0xff) ^ b1(k2);
                b2 = (PermutationBoxes.P[P_23][b2] & 0xff) ^ b2(k2);
                b3 = (PermutationBoxes.P[P_33][b3] & 0xff) ^ b3(k2);
            case 2:
                result =
                        gMDS0[(PermutationBoxes.P[P_01][(PermutationBoxes.P[P_02][b0] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)] ^
                                gMDS1[(PermutationBoxes.P[P_11][(PermutationBoxes.P[P_12][b1] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)] ^
                                gMDS2[(PermutationBoxes.P[P_21][(PermutationBoxes.P[P_22][b2] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)] ^
                                gMDS3[(PermutationBoxes.P[P_31][(PermutationBoxes.P[P_32][b3] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
                break;
        }
        return result;
    }

    //для получения 32 битного S ключа, при заданных двух ключах
    private int RS_MDS_Encode(int k0, int k1) {
        int r = k1;
        for (int i = 0; i < 4; i++) // shift 1 byte at a time
        {
            r = RS_rem(r);
        }
        r ^= k0;
        for (int i = 0; i < 4; i++) {
            r = RS_rem(r);
        }

        return r;
    }

    // g(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
    private int RS_rem(int x) {
        int b = (x >>> 24) & 0xff;
        int g2 = ((b << 1) ^
                ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
        int g3 = ((b >>> 1) ^
                ((b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0)) ^ g2;
        return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
    }

    private int LFSR1(int x) {
        return (x >> 1) ^
                (((x & 0x01) != 0) ? GF256_FDBK_2 : 0);
    }

    private int LFSR2(int x) {
        return (x >> 2) ^
                (((x & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
                (((x & 0x01) != 0) ? GF256_FDBK_4 : 0);
    }

    private int Mx_X(int x) {
        return x ^ LFSR2(x);
    } // 5B

    private int Mx_Y(int x) {
        return x ^ LFSR1(x) ^ LFSR2(x);
    } // EF

    private int b0(int x) {
        return x & 0xff;
    }

    private int b1(int x) {
        return (x >>> 8) & 0xff;
    }

    private int b2(int x) {
        return (x >>> 16) & 0xff;
    }

    private int b3(int x) {
        return (x >>> 24) & 0xff;
    }

    private int Fe32_0(int x) {
        return gSBox[0x000 + 2 * (x & 0xff)] ^
                gSBox[0x001 + 2 * ((x >>> 8) & 0xff)] ^
                gSBox[0x200 + 2 * ((x >>> 16) & 0xff)] ^
                gSBox[0x201 + 2 * ((x >>> 24) & 0xff)];
    }

    private int Fe32_3(int x) {
        return gSBox[0x000 + 2 * ((x >>> 24) & 0xff)] ^
                gSBox[0x001 + 2 * (x & 0xff)] ^
                gSBox[0x200 + 2 * ((x >>> 8) & 0xff)] ^
                gSBox[0x201 + 2 * ((x >>> 16) & 0xff)];
    }

    private int BytesTo32Bits(byte[] b, int p) {
        return ((b[p] & 0xff)) |
                ((b[p + 1] & 0xff) << 8) |
                ((b[p + 2] & 0xff) << 16) |
                ((b[p + 3] & 0xff) << 24);
    }

    private void Bits32ToBytes(int in, byte[] b, int offset) {
        b[offset] = (byte) in;
        b[offset + 1] = (byte) (in >> 8);
        b[offset + 2] = (byte) (in >> 16);
        b[offset + 3] = (byte) (in >> 24);
    }
}