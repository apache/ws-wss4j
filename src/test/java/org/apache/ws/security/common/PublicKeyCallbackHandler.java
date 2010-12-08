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

package org.apache.ws.security.common;

import org.apache.ws.security.PublicKeyCallback;

import java.security.KeyStore;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * A Callback Handler implementation for the case of a PublicKeyCallback
 */
public class PublicKeyCallbackHandler implements CallbackHandler {
    
    private KeyStore keyStore;
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof PublicKeyCallback) {
                PublicKeyCallback pc = (PublicKeyCallback) callbacks[i];
                java.security.PublicKey publicKey = pc.getPublicKey();
                if (publicKey == null || !pc.verifyTrust(keyStore)) {
                    throw new IOException("Authentication of public key failed");
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
    
    public void setKeyStore(KeyStore newKeyStore) {
        keyStore = newKeyStore;
    }
}
