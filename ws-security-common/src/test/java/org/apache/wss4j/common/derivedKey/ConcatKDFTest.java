package org.apache.wss4j.common.derivedKey;


import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Base64;
import java.util.StringJoiner;

class ConcatKDFTest {

    static {
        org.apache.xml.security.Init.init();
    }

    @ParameterizedTest
    @CsvSource({
            "'0000', 00000000, 1",
            "'00D8', 11011000, 1",
            "'00D0', 11010000, 1",
            "'00D0D8', 1101000011011000, 2",
            "'00D0,00D8', 1101000011011000, 2",
            "'00D0,,00D8', 1101000011011000, 2"
    })
    void testBitString(String strValue, String expectedResult, int length) throws WSSecurityException {
        // given
        String[] parameters = strValue.split(",");
        // when
        byte[] result = ConcatKDF.concatParameters(parameters);
        // then
        Assertions.assertNotNull(result);
        Assertions.assertEquals(length, result.length);
        Assertions.assertEquals(expectedResult, byteArrayToBitString(result));
    }


    @ParameterizedTest
    @CsvSource({
            "c2VjcmV0, 16, http://www.w3.org/2000/09/xmldsig#sha1, 90fot5WIjJVnR3Xhm2G6aQ==",
            "c2VjcmV0, 16, http://www.w3.org/2001/04/xmlenc#sha256, wJVDhd5VucXedKwlVuvuvg==",
            "c2VjcmV0, 16, http://www.w3.org/2001/04/xmlenc#sha512, tSx5jJ2y/5urnjE7WBxGmQ==",
            "c2VjcmV0, 32, http://www.w3.org/2000/09/xmldsig#sha1, 90fot5WIjJVnR3Xhm2G6aTCtemV3ve3bu4ZSa5QG2QA=",
            "c2VjcmV0, 32, http://www.w3.org/2001/04/xmlenc#sha256, wJVDhd5VucXedKwlVuvuvoi1FpbKCo7KAMrjRAUPJ94=",
            "c2VjcmV0, 32, http://www.w3.org/2001/04/xmlenc#sha512, tSx5jJ2y/5urnjE7WBxGmbm3t8YlX7GjyFUdXYpSdig=",
            "c2VjcmV0, 64, http://www.w3.org/2001/04/xmlenc#sha256, wJVDhd5VucXedKwlVuvuvoi1FpbKCo7KAMrjRAUPJ942wgP8PgKPJ6/p4caxADjtlrWiXMmi31An6IMbnCMdAA==",
            "c2VjcmV0, 77, http://www.w3.org/2001/04/xmlenc#sha256, wJVDhd5VucXedKwlVuvuvoi1FpbKCo7KAMrjRAUPJ942wgP8PgKPJ6/p4caxADjtlrWiXMmi31An6IMbnCMdAFa57tqAWq35nTPNcTw=",
            "c2VjcmV0, 10, http://www.w3.org/2001/04/xmlenc#sha256, wJVDhd5VucXedA==",
    })
    void testCreateKey(String base64Secret, int keySize, String digestURI, String expectedResult) throws WSSecurityException {
        byte[] secret = Base64.getDecoder().decode(base64Secret);

        ConcatKDF testInstance = new ConcatKDF(digestURI);
        byte[]  result = testInstance.createKey(secret,null, 0, keySize);

        Assertions.assertNotNull(result);
        Assertions.assertEquals(keySize, result.length);
        Assertions.assertEquals(expectedResult, Base64.getEncoder().encodeToString(result));
    }



    public static String byteArrayToBitString(byte[] bytes) {

        StringJoiner bitJoiner = new StringJoiner("");
        for (byte oneByte : bytes) {
            String result = "0000000" + Integer.toBinaryString(oneByte);
            result = result.substring(result.length() - 8);
            // to ensure leading zeros  "add one" otherwise they are omitted
            bitJoiner.add(result);
        }
        return bitJoiner.toString();

    }
}
