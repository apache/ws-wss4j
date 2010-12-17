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
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.util.List;
import java.io.IOException;

/**
 * The processor to process <code>wsc:SecurityContextToken</code>.
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class SecurityContextTokenProcessor implements Processor {

    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto,
        CallbackHandler cb, 
        WSDocInfo wsDocInfo, 
        WSSConfig config
    ) throws WSSecurityException {
        SecurityContextToken sct = new SecurityContextToken(elem);
        byte[] secret = getSecret(cb, sct);
        
        WSSecurityEngineResult result =
            new WSSecurityEngineResult(WSConstants.SCT, sct);
        wsDocInfo.addTokenElement(elem);
        result.put(WSSecurityEngineResult.TAG_ID, sct.getID());
        result.put(WSSecurityEngineResult.TAG_SECRET, secret);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Get the secret from the provided callback handler and return it.
     * 
     * @param cb
     * @param sct
     * @return The key collected using the callback handler
     */
    private byte[] getSecret(CallbackHandler cb, SecurityContextToken sct)
        throws WSSecurityException {

        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }

        WSPasswordCallback callback = 
            new WSPasswordCallback(
                sct.getIdentifier(), WSPasswordCallback.SECURITY_CONTEXT_TOKEN
            );
        try {
            Callback[] callbacks = new Callback[]{callback};
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "noKey",
                new Object[] {sct.getIdentifier()}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "noKey",
                new Object[] {sct.getIdentifier()}, 
                e
            );
        }

        return callback.getKey();
    }

}
