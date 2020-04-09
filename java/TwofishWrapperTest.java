import org.junit.jupiter.api.Test;
import sun.rmi.runtime.Log;
import twofish.TwofishWrapper;

import javax.xml.bind.DatatypeConverter;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TwofishWrapperTest {

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    String[] keysECB = {"5449ECA008FF5921155F598AF4CED4D0", "6600522E97AEB3094ED5F92AFCBCDD10", "34C8A5FB2D3D08A170D120AC6D26DBFA",
            "28530B358C1B42EF277DE6D4407FC591", "8A8AB983310ED78C8C0ECDE030B8DCA4", "48C758A6DFC1DD8B259FA165E1CE2B3C",
            "CE73C65C101680BBC251C5C16ABCF214"
    };

    String[] ptECB = {"6600522E97AEB3094ED5F92AFCBCDD10", "34C8A5FB2D3D08A170D120AC6D26DBFA", "28530B358C1B42EF277DE6D4407FC591",
            "8A8AB983310ED78C8C0ECDE030B8DCA4", "48C758A6DFC1DD8B259FA165E1CE2B3C", "CE73C65C101680BBC251C5C16ABCF214",
            "C7ABD74AA060F78B244E24C71342BA89"
    };

    String[] keysPCBC = {"9F1E4538CE2EC5B6757BD370C223D11A", "BA0CBA1EE2798C6CDA230B2F5DDA4041", "007594A275642622BE4741AD3AFE6EB2",
            "115A84C14AC9BC5350211E6B8C93083D", "0BB9AD4F5E97396E8D47F6A0AFBE54FF", "218322A3630760A897057DC127BA23F3",
            "A5AC89836422235602B4357B6D09BDDC"
    };

    String[] ptPCBC = {"E7F0CF8EF3D257E090A44D8D2161F3A2", "7E876FE7F45A7C49A6E7115307E5F554", "F99C3C371E6D9CCE4C021F91CB9542A5",
            "CCC8492C0DF96DE7E6C43DDED5CAD8F9", "10843754A2FD0902993C4E86F0BBDCBF", "1D100A2E4EFA087799D7DD798199FB6D",
            "83E21366942BCC1B79D23B731C2E2FBB"
    };

    String[] ivPCBC = {"E610339966D7B6E63FA87E335C4715B0", "2512FF262C5749DAAF58D85F9FF9915B", "BA792EBC971DAA4E64644A8267242EF3",
            "112F10633FAD9A71EE665FC6B66D668F", "1AE3298E145E853DDD66E8CB232D5CC2", "2A3A8FEC3D9059C61A428B618804770C",
            "842FAB20072543FE95B148BA4AB39E2F"
    };


    @Test
    void testModeECB() {

        for (int i = 0; i < keysECB.length; i++) {

            final byte[] encResult = TwofishWrapper.processECB(toByteArray(keysECB[i]), true,
                    toByteArray(ptECB[i]));

            final byte[] decResult = TwofishWrapper
                    .processECB(toByteArray(keysECB[i]), false, encResult);

            assertNotNull(encResult);
            assertNotNull(decResult);
            assertEquals(ptECB[i], toHexString(decResult).toUpperCase());
        }
    }

    @Test
    void testModePCBC() {

        for (int i = 0; i < keysPCBC.length; i++) {

            TwofishWrapper twofishWrapper = new TwofishWrapper(toByteArray(keysPCBC[i]), true, toByteArray(ivPCBC[i]));

            final byte[] encResult = twofishWrapper.processPCBC(toByteArray(ptPCBC[i]));

            TwofishWrapper twofishWrapperDec = new TwofishWrapper(
                    toByteArray(keysPCBC[i]), false, toByteArray(ivPCBC[i]));

            TwofishWrapper.cipher.reset();

            final byte[] decResult = twofishWrapperDec.processPCBC(encResult);

            assertNotNull(encResult);
            assertNotNull(decResult);
            assertEquals(ptPCBC[i], toHexString(decResult).toUpperCase());
        }
    }

}
