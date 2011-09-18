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
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityContext;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class X509_V3SecurityToken extends X509SecurityToken {
    private String alias = null;
    private X509Certificate[] x509Certificates;

    X509_V3SecurityToken(SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent, String id, Object processor) throws WSSecurityException {
        super(Constants.TokenType.X509V3Token, securityContext, crypto, callbackHandler, id, processor);
        this.x509Certificates = new X509Certificate[]{getCrypto().loadCertificate(new ByteArrayInputStream(binaryContent))};
    }

    protected String getAlias() throws WSSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getAliasForX509Cert(this.x509Certificates[0]);
        }
        return this.alias;
    }

    @Override
    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        return this.x509Certificates;
    }
}
