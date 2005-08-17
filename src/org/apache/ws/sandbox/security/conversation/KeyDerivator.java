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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.sandbox.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.sandbox.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.message.token.SecurityTokenReference;

import java.util.Hashtable;

/**
 * @author Ruchith
 * @version 1.0
 */

public class KeyDerivator {

    private Log log = LogFactory.getLog(KeyDerivator.class.getName());

    public byte[] generateKey(Hashtable sessionTable, String identifier) throws
            WSSecurityException, ConversationException, WSSecurityException {

        log.debug("KeyDerivator: Inside generate key");
        String[] uuidAndDerivedKeyTokenId = ConversationUtil.
                getUuidAndDerivedKeyTokenId(identifier);
        //Get the session from teh session table
        ConversationSession convSession = (ConversationSession) sessionTable.get(uuidAndDerivedKeyTokenId[0]);
        log.debug("KeyDerivator: session found: " + uuidAndDerivedKeyTokenId[0]);
        if (convSession != null) {
            int freq = convSession.getContextInfo().getFrequency(); //Key generation frequency
            if (freq == 0) { //If the frequency is zero then no need for key derivation
                return convSession.getContextInfo().getSharedSecret();
            } else { //Derived keys are required
                return deriveKey(convSession, uuidAndDerivedKeyTokenId[1]);
            }
        } else {
            /** @todo Check the list of expired sessions and figureout whether the session is expired or not */
            throw new ConversationException("Conversation Session not found");
        }
    }

    private byte[] deriveKey(ConversationSession convSession,
                             String derivedKeyTokenId) throws
            WSSecurityException, ConversationException {

        //The derived key info object of the current derived key
        DerivedKeyInfo dkInfo = (DerivedKeyInfo) convSession.getDerivedKeys().get(derivedKeyTokenId);
        SecurityTokenReference secTokRef = dkInfo.getSecurityTokenReference();
        log.debug("KeyDerivator: deriveKey: security token reference: " + secTokRef);
//        if (secTokRef != null) {
//            if (secTokRef.toString().equals("<wsse:SecurityTokenReference/>")) {//No security token reference
//                log.debug("KeyDerivator: deriveKey: No security token refernece available");
//                return deriveTokenFromContext(convSession, dkInfo);
//            } else {
//                String contextIdentifier = convSession.getContextInfo().getIdentifier();
//
//                String wsuId = secTokRef.getReference().getURI();
//
//                Element sctEle = WSSecurityUtil.getElementByWsuId(WSSConfig.getDefaultWSConfig(), secTokRef.getElement().getOwnerDocument(), wsuId);
//
//                try {
//                    SecurityContextToken sct = new SecurityContextToken(sctEle);
//                    if (contextIdentifier.equals(sct.getIdentifier()))
//                        return deriveTokenFromContext(convSession, dkInfo);
//                    else
//                        throw new ConversationException("Derivation source cannot be determined");
//                } catch (WSSecurityException secEx) {
//                    /** @todo Supporting other tokens other than SCT as the derivation source */
//                    //Here we should check whether it is some other type of a token
//                    //E.g. DerivedKeyToken
//                }
//
//                if (secTokRef.getReference().getURI().equals(contextIdentifier)) { //If the reference is to the SecurityContextToken
//                    return deriveTokenFromContext(convSession, dkInfo);
//                } else {
//                    //Derive from some other security token other than the relevent security context
//                    /** @todo Derive from some other security token other than the relevent security context
//                     * For example this can be another DerivedKeyToken
//                     * */
//                    throw new ConversationException("KeyDerivator:  Deriving from some " +
//                            "other security token other than the " +
//                            "relevent security context: Not implemented :-(");
//
//                }
//            }
//        } else { //There is no SecurityTokenRefernece
            log.debug("KeyDerivator: deriveKey: No security token refernece available");
            return deriveTokenFromContext(convSession, dkInfo);
  //      }

    }

    /**
     * Derive the key from the related security context information
     *
     * @param convSession
     * @param dkInfo
     * @return
     * @throws ConversationException
     */
    private byte[] deriveTokenFromContext(ConversationSession convSession,
                                          DerivedKeyInfo dkInfo) throws
            ConversationException {

        log.debug("KeyDerivator: deriving key from contecxt :" + convSession.getContextInfo().getIdentifier() + " for dkt: " + dkInfo.getId());
        byte[] secret = convSession.getContextInfo().getSharedSecret(); //Shared secret
        String labelAndNonce = getLabelAndNonce(convSession, dkInfo); //Label and nonce
        long keyLength = getKeyLength(convSession, dkInfo); //Length of the key to generated
        int offset = getOffset(convSession, dkInfo);
        DerivationAlgorithm derivationAlgo = AlgoFactory.getInstance(dkInfo.
                getAlgorithm()); //Derivation algorithm
        return derivationAlgo.createKey(secret, labelAndNonce, offset, keyLength);
    }

    /**
     * The label+nonce value used for the seed in calculating the derived key
     *
     * @param convSession
     * @param dkInfo
     * @return relevan label+nonce
     */
    private String getLabelAndNonce(ConversationSession convSession,
                                    DerivedKeyInfo dkInfo) throws
            ConversationException {
        String label, nonce;
        if ((label = dkInfo.getLabel()) != null || (label = convSession.getLabel()) != null) {
            if ((nonce = dkInfo.getNonce()) != null) {
                log.debug("KeyDerivator: Inside get label and nocne : " + label + nonce);
                return label + nonce;
            } else {
                throw new ConversationException("Nonce value not available");
            }
        } else {
            throw new ConversationException("Label cannot be found");
        }
    }

    /**
     * This return teh key length of the derived key to be generated
     *
     * @param convSession
     * @param dkInfo
     * @return length of the key to be returned
     * @throws ConversationException
     */
    private long getKeyLength(ConversationSession convSession,
                              DerivedKeyInfo dkInfo) throws ConversationException {

        long length;
        if ((length = dkInfo.getLength()) != -1) { //If the length info is there in the token return it
            log.debug("KeyDerivator: Inside get length: " + length);
            return length;
        } else if ((length = convSession.getKeyLength()) != -1) { //Get length info from the session
            log.debug("KeyDerivator: Inside get length: " + length);
            return length;
        } else {
            throw new ConversationException("Length information not available");
        }
    }

    /**
     * @param convSession
     * @param dkInfo
     * @return
     * @throws ConversationException
     */
    private int getOffset(ConversationSession convSession, DerivedKeyInfo dkInfo) throws
            ConversationException {
        int offset = dkInfo.getOffset();
        int generation = dkInfo.getGeneration();
        long lengthFromDkInfo = dkInfo.getLength();

        if (generation != -1 && offset != -1) { //If both generation and offset values are set
            throw new ConversationException("Generation and Offset both cannot be used simultaneously: " +
                    "Generation : " + generation +
                    "Offset : " + offset);
        } else if (convSession.getKeyLength() != -1) { //Session is configured to use fixed size keys
            if (generation == -1){
          		log.debug("Generation set to zero");
          		generation = 0;   
          return (int)convSession.getKeyLength() * generation;
//                throw new ConversationException("Generation value is not avaliable (fixed size keys are used: " +
//                        "Key size : " + convSession.getKeyLength() + ")");
            }else{
                return (int) convSession.getKeyLength() * generation;
            }    
        } else if (offset != -1) { //Fixed size keys are NOT used: The length and offset values should be available in the DKT
            return offset;
        } else if (generation != -1) { //Here length should be specified in the DKT
            if (dkInfo.getLength() != -1)
                return generation * (int) dkInfo.getLength();
            else
                throw new ConversationException("Length information not available");
        } else {
            return 0; //If generation and offset info are not available offset will be 0
        }
    }

}