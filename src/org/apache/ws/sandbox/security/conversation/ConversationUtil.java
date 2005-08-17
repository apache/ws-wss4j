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

package org.apache.ws.sandbox.security.conversation;

import org.apache.axis.encoding.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.sandbox.security.conversation.message.token.SecurityContextToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ConversationUtil {

    private static Log log = LogFactory.getLog(ConversationUtil.class.getName());

    /**
     * This is the seperator used in the identifier, which is set in the Callback class
     * when it is used to get a key from the key derivator
     * The identifier is the combination of the uuid of the security context and
     * the nonce of the derived key token using which the key should be derived
     */
    private static final String ID_SEPARATER = "$$$$";

    /**
     * Genearets the nonce for a given bit length.
     */
    public static String generateNonce(int length) {
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        byte[] nonceValue = new byte[length/8];
        random.nextBytes(nonceValue);
        return Base64.encode(nonceValue);
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
        int uuidEnd = identifier.indexOf(ConversationUtil.ID_SEPARATER);

        //Extract the uuid
        returnValue[0] = identifier.substring(0, uuidEnd);

        //Extract the DerivedKeyTokenId
        returnValue[1] = identifier.substring(uuidEnd + ConversationUtil.ID_SEPARATER.length(), identifier.length());

        return returnValue;
    }

    /**
     * This generates the identifier string using the uuig and the nonce
     *
     * @param uuid  The uuid
     * @param nonce The DerivedKeyTokenId
     * @return generated identifier string
     */
    public static String generateIdentifier(String uuid, String derivedKeyTokenId) {
        log.debug("ConversationUtil: Generating identifier. session id: " + uuid + ", dkt id: " + derivedKeyTokenId);
        return uuid + ConversationUtil.ID_SEPARATER + derivedKeyTokenId;
    }

    public static String generateUuid() {
        //This is wrong 
        //Replace this with the proper code for Uuid generation
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        byte[] nonceValue = new byte[32];
        random.nextBytes(nonceValue);
        return Base64.encode(nonceValue);
    }

    /**
     * Method genericID
     *
     * @return
     */
    public static String genericID() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            int i = random.nextInt(Integer.MAX_VALUE);
            return String.valueOf(i);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    /**
     * The method takes in a DerivedKetToken and returns the uuid of the corresponding SCT.
     * There can be serveral cases.
     * Case 1: If there is only one SCT in the owner docuemter it is the corresponding SCT
     * Case 2: If there are two resolve them by Id
     * Case 3: The corresponding SCT can be mentioned in properties as well.
     *
     * @param dkToken
     * @return
     */

    public static SecurityContextToken getSCT(DerivedKeyToken dkToken) throws ConversationException {
        //TODO : Case 2 and Case 3 throw proper exception
        String uuid = null;
        Document doc = dkToken.getElement().getOwnerDocument();
        NodeList ndList = doc.getElementsByTagNameNS(ConversationConstants.WSC_NS, ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
        if (ndList.getLength() == 0) {
            throw new ConversationException("Cannot find SCT");
        }
        try {
            Element ele = (Element) ndList.item(0);
            SecurityContextToken sct = new SecurityContextToken(ele);
            return sct;
        } catch (WSSecurityException e) {
            //e.printStackTrace();
            throw new ConversationException(e.getMessage());
        }
    }

}
