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

package org.apache.ws.security.action;

import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecEncrypt;
import org.w3c.dom.Document;

public class EncryptionAction implements Action {
    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
        WSSecEncrypt wsEncrypt = new WSSecEncrypt(reqData.getWssConfig());

        if (reqData.getEncKeyId() != 0) {
            wsEncrypt.setKeyIdentifierType(reqData.getEncKeyId());
        }
        if (reqData.getEncKeyId() == WSConstants.EMBEDDED_KEYNAME) {
            String encKeyName = handler.getString(WSHandlerConstants.ENC_KEY_NAME,
                    reqData.getMsgContext());
            wsEncrypt.setEmbeddedKeyName(encKeyName);
            CallbackHandler callbackHandler = 
                handler.getCallbackHandler(
                    WSHandlerConstants.ENC_CALLBACK_CLASS,
                    WSHandlerConstants.ENC_CALLBACK_REF, 
                    reqData
                );
            WSPasswordCallback passwordCallback = 
                handler.getPasswordCB(reqData.getEncUser(), actionToDo, callbackHandler, reqData);
            byte[] embeddedKey = passwordCallback.getKey();
            wsEncrypt.setKey(embeddedKey);
            wsEncrypt.setDocument(doc);
        }
        if (reqData.getEncSymmAlgo() != null) {
            wsEncrypt.setSymmetricEncAlgorithm(reqData.getEncSymmAlgo());
        }
        if (reqData.getEncKeyTransport() != null) {
            wsEncrypt.setKeyEnc(reqData.getEncKeyTransport());
        }
        if (reqData.getEncDigestAlgorithm() != null) {
            wsEncrypt.setDigestAlgorithm(reqData.getEncDigestAlgorithm());
        }
        
        wsEncrypt.setUserInfo(reqData.getEncUser());
        wsEncrypt.setUseThisCert(reqData.getEncCert());
        Crypto crypto = reqData.getEncCrypto();
        boolean enableRevocation = Boolean.valueOf(handler.getStringOption(WSHandlerConstants.ENABLE_REVOCATION));
        if (enableRevocation && crypto != null) {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(reqData.getEncUser());
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            if (certs != null && certs.length > 0) {
                crypto.verifyTrust(certs, enableRevocation);
            }
        }
        if (reqData.getEncryptParts().size() > 0) {
            wsEncrypt.setParts(reqData.getEncryptParts());
        }
        if (!reqData.getEncryptSymmetricEncryptionKey()) {
            CallbackHandler callbackHandler = 
                handler.getPasswordCallbackHandler(reqData);
            WSPasswordCallback passwordCallback = 
                handler.getPasswordCB(reqData.getEncUser(), actionToDo, callbackHandler, reqData);
            wsEncrypt.setEphemeralKey(passwordCallback.getKey());
            wsEncrypt.setEncryptSymmKey(reqData.getEncryptSymmetricEncryptionKey());
        }
        try {
            wsEncrypt.build(doc, reqData.getEncCrypto(), reqData.getSecHeader());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("Error during encryption: ", e);
        }
    }
}
