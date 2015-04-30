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

package org.apache.wss4j.dom.processor;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;

public final class X509Util {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(X509Util.class);
    
    private X509Util() {
        // Complete
    }

    public static boolean isContent(Node encBodyData) {
        if (encBodyData != null) {
            String typeStr = ((Element)encBodyData).getAttributeNS(null, "Type");
            if (typeStr != null) {
                 return typeStr.equals(WSConstants.ENC_NS + "Content");
            }
        }
        return false;
    }

    public static String getEncAlgo(Node encBodyData) throws WSSecurityException {
        Element tmpE = 
            XMLUtils.getDirectChildElement(
                encBodyData, "EncryptionMethod", WSConstants.ENC_NS
            );
        String symEncAlgo = null;
        if (tmpE != null) {
            symEncAlgo = tmpE.getAttributeNS(null, "Algorithm");
            if (symEncAlgo == null || "".equals(symEncAlgo)) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noEncAlgo"
                );
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sym Enc Algo: " + symEncAlgo);
        }
        return symEncAlgo;
    }

    protected static SecretKey getSharedKey(
        Element keyInfoElem,
        String algorithm,
        CallbackHandler cb
    ) throws WSSecurityException {
        String keyName = null;
        Element keyNmElem = 
            XMLUtils.getDirectChildElement(
                keyInfoElem, "KeyName", WSConstants.SIG_NS
            );
        if (keyNmElem != null) {
            keyName = XMLUtils.getElementText(keyNmElem);
        }
        if (keyName == null || keyName.length() <= 0) {
            LOG.debug("No Key Name available");
        }
        WSPasswordCallback pwCb = 
                new WSPasswordCallback(keyName, WSPasswordCallback.SECRET_KEY);
        try {
            cb.handle(new Callback[]{pwCb});
        } catch (IOException | UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, e,
                "noPassword",
                new Object[] {keyName});
        }
        byte[] decryptedData = pwCb.getKey();
        if (decryptedData == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "noPassword",
                new Object[] {keyName});
        }
        return KeyUtils.prepareSecretKey(algorithm, decryptedData);
    }

}
