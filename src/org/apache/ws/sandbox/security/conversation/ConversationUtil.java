/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.conversation;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Class ConversationUtil
 */
public class ConversationUtil {

    /**
     * This is the seperator used in the identifier, which is set in the Callback class
     * when it is used to get a key from the key derivator
     * The identifier is the combination of the uuid of the security context and
     * the nonce of the derived key token using which the key should be derived
     */
    private static final String ID_SEPARATER = "$$$$";

    // PX2HKO4TotXxjI6NuZ3MVQ==
    // 4gwgpDksuZsRy7bnontCw==

    /**
     * Genearets the nonce for a given length.
     * More comments...
     * 
     * @param length 
     * @return 
     */
    public String generateNonce(int length) {
        String nonce = "";    // he he
        Random nonceIntGen = new Random();
        float tempVal;
        String allChars =
                "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz/=1234567890";

        // need more ???//
        for (int i = 0; i <= length; i++) {
            tempVal = nonceIntGen.nextFloat();
            int lengthOfCharSet = allChars.length() - 1;
            int charAt = Math.round(lengthOfCharSet * tempVal);
            nonce += allChars.charAt(charAt);
        }
        return nonce;
    }

    /**
     * @param identifier 
     * @return 
     * @see getUuidAndDerivedKeyTokenId()
     */
    public static String getDerivedKeyTokenId(String identifier) {
        return getUuidAndDerivedKeyTokenId(identifier)[1];
    }

    /**
     * @param identifier 
     * @return 
     * @see getUuidAndDerivedKeyTokenId()
     */
    public static String getUuid(String identifier) {
        return getUuidAndDerivedKeyTokenId(identifier)[0];
    }

    /**
     * This extracts the Uuid and the DerivedKeyTokenId from the identifier sent in
     * 
     * @param identifier The identifier in uuid[ConvUtil.ID_SEPARATOR]nonce format
     * @return A String arrasy of size 2 with uuid as the forst character and the nonce as the second
     */
    public static String[] getUuidAndDerivedKeyTokenId(String identifier) {
        String[] returnValue = new String[2];
        int uuidEnd =
                identifier.indexOf(ConversationUtil.ID_SEPARATER);

        // Extract the uuid
        returnValue[0] = identifier.substring(0, uuidEnd);

        // Extract the DerivedKeyTokenId
        returnValue[1] = identifier.substring(uuidEnd + ConversationUtil.ID_SEPARATER.length(),
                identifier.length());
        return returnValue;
    }

    /**
     * This generates the identifier string using the uuig and the nonce
     * 
     * @param uuid              The uuid
     * @param nonce             The DerivedKeyTokenId
     * @param derivedKeyTokenId 
     * @return generated identifier string
     */
    public static String generateIdentifier(String uuid,
                                            String derivedKeyTokenId) {
        return uuid + ConversationUtil.ID_SEPARATER + derivedKeyTokenId;
    }

    /**
     * Method genericID
     * 
     * @return 
     */
    public static String genericID() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] genIDValue = new byte[6];
            random.nextBytes(genIDValue);
            return new String(genIDValue);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
