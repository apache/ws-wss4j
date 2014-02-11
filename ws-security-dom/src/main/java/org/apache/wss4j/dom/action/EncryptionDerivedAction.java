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

import org.apache.wss4j.common.EncryptionActionToken;
import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.w3c.dom.Document;

public class EncryptionDerivedAction implements Action {
    
    public void execute(WSHandler handler, SecurityActionToken actionToken,
                        Document doc, RequestData reqData)
            throws WSSecurityException {
        CallbackHandler callbackHandler = reqData.getCallbackHandler();
        if (callbackHandler == null) {
            callbackHandler = handler.getPasswordCallbackHandler(reqData);
        }
        
        EncryptionActionToken encryptionToken = null;
        if (actionToken instanceof EncryptionActionToken) {
            encryptionToken = (EncryptionActionToken)actionToken;
        }
        if (encryptionToken == null) {
            encryptionToken = reqData.getEncryptionToken();
        }
        
        WSPasswordCallback passwordCallback = 
            handler.getPasswordCB(encryptionToken.getUser(), WSConstants.DKT_ENCR, callbackHandler, reqData);
        WSSecDKEncrypt wsEncrypt = new WSSecDKEncrypt(reqData.getWssConfig());

        if (encryptionToken.getKeyIdentifierId() != 0) {
            wsEncrypt.setKeyIdentifierType(encryptionToken.getKeyIdentifierId());
        }

        if (encryptionToken.getSymmetricAlgorithm() != null) {
            wsEncrypt.setSymmetricEncAlgorithm(encryptionToken.getSymmetricAlgorithm());
        }
        wsEncrypt.setUserInfo(encryptionToken.getUser(), passwordCallback.getPassword());
        
        WSSecEncryptedKey encrKeyBuilder = null;
        String sctId = null;
        
        if (reqData.isUse200512Namespace()) {
            wsEncrypt.setWscVersion(ConversationConstants.VERSION_05_12);
        } else {
            wsEncrypt.setWscVersion(ConversationConstants.VERSION_05_02);
        }
        
        if (encryptionToken.getDerivedKeyLength() > 0) {
            wsEncrypt.setDerivedKeyLength(encryptionToken.getDerivedKeyLength());
        }
        
        String derivedKeyTokenReference = encryptionToken.getDerivedKeyTokenReference();
        if ("SecurityContextToken".equals(derivedKeyTokenReference)) {
            sctId = IDGenerator.generateID("uuid:");
            if (reqData.isUse200512Namespace()) {
                wsEncrypt.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                wsEncrypt.setCustomValueType(WSConstants.WSC_SCT);
            }
            
            wsEncrypt.setExternalKey(passwordCallback.getKey(), sctId);
            
        } else {
            encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo(encryptionToken.getUser());
            if (encryptionToken.getDerivedKeyIdentifier() != 0) {
                encrKeyBuilder.setKeyIdentifierType(encryptionToken.getDerivedKeyIdentifier());
            } else {
                encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            }
            
            if (encryptionToken.getKeyTransportAlgorithm() != null) {
                encrKeyBuilder.setKeyEncAlgo(encryptionToken.getKeyTransportAlgorithm());
            }
            if (encryptionToken.getDigestAlgorithm() != null) {
                encrKeyBuilder.setDigestAlgorithm(encryptionToken.getDigestAlgorithm());
            }
            if (encryptionToken.getMgfAlgorithm() != null) {
                encrKeyBuilder.setMGFAlgorithm(encryptionToken.getMgfAlgorithm());
            }
            
            encrKeyBuilder.prepare(doc, encryptionToken.getCrypto());

            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            wsEncrypt.setExternalKey(ek, tokenIdentifier);
            wsEncrypt.setCustomValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        }
        wsEncrypt.setAttachmentCallbackHandler(reqData.getAttachmentCallbackHandler());

        try {
            List<WSEncryptionPart> parts = encryptionToken.getParts();
            if (parts == null || parts.isEmpty()) {
                WSEncryptionPart encP = new WSEncryptionPart(reqData.getSoapConstants()
                        .getBodyQName().getLocalPart(), reqData.getSoapConstants()
                        .getEnvelopeURI(), "Content");
                parts = new ArrayList<WSEncryptionPart>();
                parts.add(encP);
            }
            
            wsEncrypt.setParts(parts);
            wsEncrypt.build(doc, reqData.getSecHeader());
            
            wsEncrypt.prependDKElementToHeader(reqData.getSecHeader());
            
            if (encrKeyBuilder != null) {
                encrKeyBuilder.prependToHeader(reqData.getSecHeader());
            } else if (sctId != null) {
                SecurityContextToken sct = new SecurityContextToken(doc, sctId);
                WSSecurityUtil.prependChildElement(reqData.getSecHeader().getSecurityHeader(), sct.getElement());
            }
            
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                          "empty", e, "Error during Encryption: ");
        }
    }

}
