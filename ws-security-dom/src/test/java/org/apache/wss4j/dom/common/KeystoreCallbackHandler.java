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

package org.apache.wss4j.dom.common;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A Callback Handler implementation for the case of finding a password to access a
 * cert/private key in a keystore.
 */
public class KeystoreCallbackHandler implements CallbackHandler {

    private final Map<String, String> users = new HashMap<>();

    public KeystoreCallbackHandler() {
        users.put("wss86", "security");
        users.put("wss40", "security");
        users.put("wss40rev", "security");
        users.put("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        users.put("regexp", "security");
        users.put("x448", "security");
        users.put("x25519", "security");
        users.put("secp256r1", "security");
        users.put("secp384r1", "security");
        users.put("secp521r1", "security");
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callback;
                if (users.containsKey(pc.getIdentifier())) {
                    pc.setPassword(users.get(pc.getIdentifier()));
                } else if (WSPasswordCallback.PASSWORD_ENCRYPTOR_PASSWORD == pc.getUsage()) {
                    pc.setPassword("this-is-a-secret");
                }
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }
}
