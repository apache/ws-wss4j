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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.message.token.SecurityTokenReference;

import java.util.Hashtable;

/**
 * Class KeyDerivator
 */
public class KeyDerivator {

    /**
     * Field useFixedSizeKeys
     */
    private boolean useFixedSizeKeys = true;

    /**
     * Field keySize
     */
    private long keySize = 16;

    /**
     * Constructor KeyDerivator
     * 
     * @param useFixedSizeKeys 
     * @param keySize          
     */
    public KeyDerivator(boolean useFixedSizeKeys, long keySize) {
        this.useFixedSizeKeys = useFixedSizeKeys;
        this.keySize = keySize;
    }

    /**
     * Method generateKey
     * 
     * @param sessionTable 
     * @param identifier   
     * @return 
     * @throws WSSecurityException   
     * @throws ConversationException 
     * @throws WSSecurityException   
     */
    public String generateKey(Hashtable sessionTable, String identifier)
            throws WSSecurityException, ConversationException,
            WSSecurityException {
        String[] uuidAndDerivedKeyTokenId =
                ConversationUtil.getUuidAndDerivedKeyTokenId(identifier);

        // Get the session from teh session table
        ConversationSession convSession =
                (ConversationSession) sessionTable.get(uuidAndDerivedKeyTokenId[0]);
        int freq =
                convSession.getContextInfo().getFrequency();

        // Key generation frequency
        if (freq == 0) {
            // If the frequency is zero then no need for key derivation
            return convSession.getContextInfo().getSharedSecret().toString();
        } else {    // Derived keys are required
            return deriveKey(convSession, uuidAndDerivedKeyTokenId[1]);
        }
    }

    /**
     * Method deriveKey
     * 
     * @param convSession       
     * @param derivedKeyTokenId 
     * @return 
     * @throws WSSecurityException   
     * @throws ConversationException 
     */
    private String deriveKey(ConversationSession convSession, String derivedKeyTokenId)
            throws WSSecurityException, ConversationException {
        // The derived key info object of the current derived key
        DerivedKeyInfo dkInfo =
                (DerivedKeyInfo) convSession.getDerivedKeys().get(derivedKeyTokenId);
        SecurityTokenReference secTokRef = dkInfo.getSecurityTokenReference();
        if (secTokRef != null) {
            String contextIdentifier =
                    convSession.getContextInfo().getIdentifier();
            if (secTokRef.getReference().getURI().equals(contextIdentifier)) {
                // If the reference is to the SecurityContextToken
                return deriveTokenFromContext(convSession, dkInfo);
            }
        } else {    // There is no SecurityTokenRefernece
            return deriveTokenFromContext(convSession, dkInfo);
        }
        return "ThisIsNotDoneYet";
    }

    /**
     * Method deriveTokenFromContext
     * 
     * @param convSession 
     * @param dkInfo      
     * @return 
     * @throws ConversationException 
     */
    private String deriveTokenFromContext(ConversationSession convSession, DerivedKeyInfo dkInfo)
            throws ConversationException {
        String secret =
                convSession.getContextInfo().getSharedSecret().toString();

        // If the derivator is not configurad to use fixed size keys and there is no length information
        if ((!useFixedSizeKeys) && (dkInfo.getLength() == -1)) {
        }
        if (dkInfo.getGeneration() != -1) {    // Generation info present
        } else {                               // No generation info
        }
        return "";
    }

    /**
     * Method useFixedSizeKeys
     * 
     * @param usage 
     */
    public void useFixedSizeKeys(boolean usage) {
    }

    /**
     * Method useFixedSizeKeys
     * 
     * @param usage  
     * @param length 
     */
    public void useFixedSizeKeys(boolean usage, long length) {
    }
}
