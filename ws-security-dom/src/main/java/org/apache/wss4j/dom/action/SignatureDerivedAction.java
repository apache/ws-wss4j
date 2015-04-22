/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.dom.action;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SignatureDerivedAction extends AbstractDerivedAction implements Action {
    
    public void execute(WSHandler handler, SecurityActionToken actionToken,
                        Document doc, RequestData reqData)
            throws WSSecurityException {
        CallbackHandler callbackHandler = reqData.getCallbackHandler();
        if (callbackHandler == null) {
            callbackHandler = handler.getPasswordCallbackHandler(reqData);
        }
        
        SignatureActionToken signatureToken = null;
        if (actionToken instanceof SignatureActionToken) {
            signatureToken = (SignatureActionToken)actionToken;
        }
        if (signatureToken == null) {
            signatureToken = reqData.getSignatureToken();
        }
        
        WSPasswordCallback passwordCallback = 
            handler.getPasswordCB(signatureToken.getUser(), WSConstants.DKT_SIGN, callbackHandler, reqData);
        WSSecDKSign wsSign = new WSSecDKSign(reqData.getWssConfig());

        if (signatureToken.getSignatureAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(signatureToken.getSignatureAlgorithm());
        }
        if (signatureToken.getDigestAlgorithm() != null) {
            wsSign.setDigestAlgorithm(signatureToken.getDigestAlgorithm());
        }
        if (signatureToken.getC14nAlgorithm() != null) {
            wsSign.setSigCanonicalization(signatureToken.getC14nAlgorithm());
        }
        wsSign.setUserInfo(signatureToken.getUser(), passwordCallback.getPassword());
        
        if (reqData.isUse200512Namespace()) {
            wsSign.setWscVersion(ConversationConstants.VERSION_05_12);
        } else {
            wsSign.setWscVersion(ConversationConstants.VERSION_05_02);
        }
        
        if (signatureToken.getDerivedKeyLength() > 0) {
            wsSign.setDerivedKeyLength(signatureToken.getDerivedKeyLength());
        }
        
        Element tokenElement = 
            setupTokenReference(reqData, signatureToken, wsSign, passwordCallback, doc);
        wsSign.setAttachmentCallbackHandler(reqData.getAttachmentCallbackHandler());

        try {
            List<WSEncryptionPart> parts = signatureToken.getParts();
            if (parts == null || parts.isEmpty()) {
                WSEncryptionPart encP = new WSEncryptionPart(reqData.getSoapConstants()
                        .getBodyQName().getLocalPart(), reqData.getSoapConstants()
                        .getEnvelopeURI(), "Content");
                parts = new ArrayList<WSEncryptionPart>();
                parts.add(encP);
            }
            
            wsSign.setParts(parts);
            wsSign.prepare(doc, reqData.getSecHeader());
            
            List<javax.xml.crypto.dsig.Reference> referenceList = 
                wsSign.addReferencesToSign(parts, reqData.getSecHeader());
            
            // Put the DerivedKeyToken Element in the right place in the security header
            Node nextSibling = null;
            if (tokenElement == null 
                && "EncryptedKey".equals(signatureToken.getDerivedKeyTokenReference())) {
                nextSibling = findEncryptedKeySibling(reqData);
            } else if (tokenElement == null 
                && "SecurityContextToken".equals(signatureToken.getDerivedKeyTokenReference())) {
                nextSibling = findSCTSibling(reqData);
            }
            
            if (nextSibling == null) {
                wsSign.computeSignature(referenceList);
            } else {
                wsSign.computeSignature(referenceList, true, (Element)nextSibling);
            }
            
            if (nextSibling == null) {
                wsSign.prependDKElementToHeader(reqData.getSecHeader());
            } else {
                reqData.getSecHeader().getSecurityHeader().insertBefore(
                    wsSign.getdktElement(), wsSign.getSignatureElement());
            }
            
            if (tokenElement != null) {
                WSSecurityUtil.prependChildElement(reqData.getSecHeader().getSecurityHeader(), tokenElement);
            }
            
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", e, "Error during Signature: ");
        }
    }
    
    private Element setupTokenReference(
        RequestData reqData, SignatureActionToken signatureToken,
        WSSecDKSign wsSign, WSPasswordCallback passwordCallback,
        Document doc
    ) throws WSSecurityException {
        String derivedKeyTokenReference = signatureToken.getDerivedKeyTokenReference();

        if ("EncryptedKey".equals(derivedKeyTokenReference)) {
            wsSign.setCustomValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            // See if an EncryptionAction has already set up an EncryptedKey
            if (reqData.getEncryptionToken() != null && reqData.getEncryptionToken().getKey() != null
                && reqData.getEncryptionToken().getKeyIdentifier() != null) {
                byte[] ek = reqData.getEncryptionToken().getKey();
                String tokenIdentifier = reqData.getEncryptionToken().getKeyIdentifier();
                wsSign.setExternalKey(ek, tokenIdentifier);
                return null;
            } else {
                WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
                encrKeyBuilder.setUserInfo(signatureToken.getUser());
                if (signatureToken.getDerivedKeyIdentifier() != 0) {
                    encrKeyBuilder.setKeyIdentifierType(signatureToken.getDerivedKeyIdentifier());
                } else {
                    encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
                }
                encrKeyBuilder.prepare(doc, signatureToken.getCrypto());

                byte[] ek = encrKeyBuilder.getEphemeralKey();
                String tokenIdentifier = encrKeyBuilder.getId();

                signatureToken.setKey(ek);
                signatureToken.setKeyIdentifier(tokenIdentifier);
               
                wsSign.setExternalKey(ek, tokenIdentifier);
                return encrKeyBuilder.getEncryptedKeyElement();
            }
        } else if ("SecurityContextToken".equals(derivedKeyTokenReference)) {
            if (reqData.isUse200512Namespace()) {
                wsSign.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                wsSign.setCustomValueType(WSConstants.WSC_SCT);
            }
            
            // See if a EncryptionDerivedAction has already set up a SecurityContextToken
            if (reqData.getEncryptionToken() != null && reqData.getEncryptionToken().getKey() != null
                && reqData.getEncryptionToken().getKeyIdentifier() != null) {
                byte[] secret = reqData.getEncryptionToken().getKey();
                String tokenIdentifier = reqData.getEncryptionToken().getKeyIdentifier();
                wsSign.setExternalKey(secret, tokenIdentifier);
                return null;
            }  else {
                String tokenIdentifier = IDGenerator.generateID("uuid:");
                wsSign.setExternalKey(passwordCallback.getKey(), tokenIdentifier);
                
                signatureToken.setKey(passwordCallback.getKey());
                signatureToken.setKeyIdentifier(tokenIdentifier);
                
                int version = ConversationConstants.VERSION_05_12;
                if (!reqData.isUse200512Namespace()) {
                    version = ConversationConstants.VERSION_05_02;
                }
                
                SecurityContextToken sct = new SecurityContextToken(version, doc, tokenIdentifier);
                return sct.getElement();
            }
        } else {
            // DirectReference

            if (signatureToken.getDerivedKeyIdentifier() != 0) {
                wsSign.setKeyIdentifierType(signatureToken.getDerivedKeyIdentifier());
            } else {
                wsSign.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            }

            byte[] key = null;
            if (passwordCallback.getKey() != null) {
                key = passwordCallback.getKey();
            } else if (signatureToken.getKey() != null) {
                key = signatureToken.getKey();
            } else {
                Crypto crypto = signatureToken.getCrypto();
                key = crypto.getPrivateKey(signatureToken.getUser(), passwordCallback.getPassword()).getEncoded();
            }
            wsSign.setCrypto(signatureToken.getCrypto());
            wsSign.setExternalKey(key, (String)null);
            
            return null;
        }
    }
}
