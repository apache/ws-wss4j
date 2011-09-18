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
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSecurityToken implements SecurityToken {

    private Crypto crypto;
    private CallbackHandler callbackHandler;
    private String id;
    private Object processor;

    AbstractSecurityToken(Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.id = id;
        this.processor = processor;
    }

    AbstractSecurityToken(String id) {
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public Object getProcessor() {
        return processor;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        return null;
    }

    public void verify() throws WSSecurityException {
    }
}
