package twofish;

import java.util.Arrays;
import java.util.Vector;
import javax.xml.bind.DatatypeConverter;

public class Main {

    // вектор инициализации — случайное число
    //Размер (длина) IV равна размеру блока

    static int[] key = { 0x28, 0x2B, 0xE7,
            0xE4, 0xFA, 0x1F,
            0xBD, 0xC2, 0x96,
            0x61, 0x28, 0x6F,
            0x1F, 0x31, 0x0B,
            0x7E
    };
    static int[] plainText= { 0x28, 0x2B, 0xE7, 0xE4, 0xFA, 0x1F, 0xBD, 0xC2, 0x96, 0x61, 0x28, 0x6F, 0x1F, 0x31, 0x0B, 0x7E
    };

    static int[] decKey = {0x35, 0xD2, 0x4D, 0xEE, 0xF3, 0x8E, 0x98, 0xA4, 0x9F, 0xE6, 0xB3, 0x85, 0xD9, 0x93, 0x0F, 0xC0};
    static int[] decpt = {0xD5, 0x18, 0x7E, 0x7D, 0x6B, 0x8B, 0xE9, 0x51, 0x7D, 0xAC, 0x4A, 0x8A, 0xF4, 0xA5,0x52, 0xEA};

    //работает в паре с key=zeroesBytes ecb vt
    //ecb vk тоже работает
    static int[] vtpt = {
            0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    };
    static int[] tblpt = {
            0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
    };

    public static void main(String[] args) {

        encryptECB(zeroesBytes, zeroesBytes);


        encryptCBC(toByteArray("3CC3B181E1495D0495D652B66921DA0F"), toByteArray("BE938D30FAB43B71F2E114E9C0529299"), toByteArray("3CC3B181E1495D0495D652B66921DA0F"));

    }

    private static void encryptECB(int[] key, int[] plainText){

        final byte[] encResult = TwofishWrapper.processECB(Util.unsignedToSigned(key), true,
                Util.unsignedToSigned(plainText));

        final byte[] decResult = TwofishWrapper
                .processECB(Util.unsignedToSigned(key), false, encResult);

        System.out.println(" ECB MODE PT:  " + Util.bytesToHex(Util.unsignedToSigned(plainText)) + "\n DEC result:  "
                + Util.bytesToHex(decResult)
                + "\n encRes: " + Util.bytesToHex(encResult)
        );
    }


    private static void encryptCBC(byte[] key, byte[] plainText, byte[] iv){
        TwofishWrapper twofishWrapper = new TwofishWrapper(key, true, iv);

        final byte[] encResult = twofishWrapper.processCBC(plainText);

        TwofishWrapper twofishWrapperDec = new TwofishWrapper(
                key, false,  iv);

        TwofishWrapper.cipher.reset();

        final byte[] decResult = twofishWrapperDec.processCBC(encResult);

        System.out.println(" CBC MODE :PT:  " + Util.bytesToHex(plainText) + "\n DEC result:  "
                + Util.bytesToHex(decResult)
                + "\n encRes: " + Util.bytesToHex(encResult)
        );

    }
    private static void decryptionECB(){

        final byte[] decResult = TwofishWrapper
                .processECB(Util.unsignedToSigned(zeroesBytes), false, Util.unsignedToSigned(zeroesBytes));
        System.out.println("\n DEC result:  "
                + Util.bytesToHex(decResult));
    }



    static int[] zeroesBytes = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    };
    static int[] plainTextIval= { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    };

    static int[] keyIval192 = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    static int[] ptIval192 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    };

    private static void ecbIval() {
        final byte[] encResult = TwofishWrapper.processECB(Util.unsignedToSigned(keyIval192), true,
                Util.unsignedToSigned(ptIval192));

        final byte[] decResult = TwofishWrapper
                .processECB(Util.unsignedToSigned(keyIval192), false, encResult);

        System.out.println(Util.bytesToHex(Util.unsignedToSigned(ptIval192)) + " bbbbbbbb " + Util.bytesToHex(decResult)
                + " bbbbbbbb " + Util.bytesToHex(encResult) + " bbbbbbbb " + Arrays.toString(encResult) + encResult.length
        );

        Byte b = new Byte("");

        Vector<Byte> byteVector = new Vector<>();
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
}
