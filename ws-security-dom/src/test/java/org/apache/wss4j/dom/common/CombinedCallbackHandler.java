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

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

/**
 * A combined Callback Handler implementation which wraps the SecretKeyCallbackHandler and the 
 * KeystoreCallbackHandler.
 */
public class CombinedCallbackHandler implements CallbackHandler {
    
    private final CallbackHandler secretCallbackHandler;
    private final CallbackHandler keystoreCallbackHandler;
    
    public CombinedCallbackHandler(
        CallbackHandler secretCallbackHandler, CallbackHandler keystoreCallbackHandler
    ) {
        this.secretCallbackHandler = secretCallbackHandler;
        this.keystoreCallbackHandler = keystoreCallbackHandler;
    }
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                if ((pc.getUsage() == WSPasswordCallback.SECRET_KEY)
                    || (pc.getUsage() == WSPasswordCallback.SECURITY_CONTEXT_TOKEN)) {
                    secretCallbackHandler.handle(callbacks);
                } else {
                    keystoreCallbackHandler.handle(callbacks);
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
