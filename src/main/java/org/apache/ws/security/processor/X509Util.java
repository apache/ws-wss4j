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

package org.apache.ws.security.processor;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public final class X509Util {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(X509Util.class);
    
    private X509Util() {
        // Complete
    }

    public static boolean isContent(Node encBodyData) {
        if (encBodyData != null) {
            String typeStr = ((Element)encBodyData).getAttribute("Type");
            if (typeStr != null) {
                 return typeStr.equals(WSConstants.ENC_NS + "Content");
            }
        }
        return true;
    }

    public static String getEncAlgo(Node encBodyData) throws WSSecurityException {
        Element tmpE = 
            WSSecurityUtil.getDirectChildElement(
                encBodyData, "EncryptionMethod", WSConstants.ENC_NS
            );
        String symEncAlgo = null;
        if (tmpE != null) {
            symEncAlgo = tmpE.getAttribute("Algorithm");
            if (symEncAlgo == null || "".equals(symEncAlgo)) {
                throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo"
                );
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Sym Enc Algo: " + symEncAlgo);
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
            WSSecurityUtil.getDirectChildElement(
                keyInfoElem, "KeyName", WSConstants.SIG_NS
            );
        if (keyNmElem != null) {
            
            Node node = keyNmElem.getFirstChild();
            StringBuilder builder = new StringBuilder();
            while (node != null) {
                if (Node.TEXT_NODE == node.getNodeType()) {
                    builder.append(((Text)node).getData());
                }
                node = node.getNextSibling();
            }
            keyName = builder.toString();
        }
        if (keyName == null || keyName.length() <= 0) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyname");
        }
        WSPasswordCallback pwCb = new WSPasswordCallback(keyName, WSPasswordCallback.SECRET_KEY);
        try {
            cb.handle(new Callback[]{pwCb});
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{keyName}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{keyName}, 
                e
            );
        }
        byte[] decryptedData = pwCb.getKey();
        if (decryptedData == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{keyName}
            );
        }
        return WSSecurityUtil.prepareSecretKey(algorithm, decryptedData);
    }

}
