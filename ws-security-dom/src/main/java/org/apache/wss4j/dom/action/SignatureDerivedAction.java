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

public class SignatureDerivedAction implements Action {
    
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
        
        WSSecEncryptedKey encrKeyBuilder = null;
        String sctId = null;
        
        String derivedKeyTokenReference = signatureToken.getDerivedKeyTokenReference();
        if ("EncryptedKey".equals(derivedKeyTokenReference)) {
            encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo(signatureToken.getUser());
            encrKeyBuilder.setKeyIdentifierType(signatureToken.getKeyIdentifierId());
            encrKeyBuilder.prepare(doc, signatureToken.getCrypto());

            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();
            
            wsSign.setExternalKey(ek, tokenIdentifier);
            wsSign.setCustomValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        } else if ("SecurityContextToken".equals(derivedKeyTokenReference)) {
            sctId = IDGenerator.generateID("uuid:");
            wsSign.setCustomValueType(WSConstants.WSC_SCT);
            
            wsSign.setExternalKey(passwordCallback.getKey(), sctId);
            
        } else {
            // DirectReference
            
            if (signatureToken.getKeyIdentifierId() != 0) {
                wsSign.setKeyIdentifierType(signatureToken.getKeyIdentifierId());
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
        }
        
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
            wsSign.build(doc, reqData.getSecHeader());
            
            wsSign.prependDKElementToHeader(reqData.getSecHeader());
            
            if (encrKeyBuilder != null) {
                encrKeyBuilder.prependToHeader(reqData.getSecHeader());
            } else if (sctId != null) {
                SecurityContextToken sct = new SecurityContextToken(doc, sctId);
                WSSecurityUtil.prependChildElement(reqData.getSecHeader().getSecurityHeader(), sct.getElement());
            }
            
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", e, "Error during Signature: ");
        }
    }

}
