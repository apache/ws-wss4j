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
package org.apache.ws.security.stax.impl.securityToken;

import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class X509PKIPathv1SecurityToken extends X509SecurityToken {

    private String alias = null;
    private X509Certificate[] x509Certificates;

    X509PKIPathv1SecurityToken(WSSecurityContext wsSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
                               byte[] binaryContent, String id, WSSConstants.KeyIdentifierType keyIdentifierType) throws XMLSecurityException {
        super(WSSConstants.X509PkiPathV1Token, wsSecurityContext, crypto, callbackHandler, id, keyIdentifierType);

        InputStream in = new ByteArrayInputStream(binaryContent);
        try {
            CertPath certPath = getCrypto().getCertificateFactory().generateCertPath(in);
            List<? extends Certificate> l = certPath.getCertificates();
            X509Certificate[] certs = new X509Certificate[l.size()];
            Iterator<? extends Certificate> iterator = l.iterator();
            for (int i = 0; i < l.size(); i++) {
                certs[i] = (X509Certificate) iterator.next();
            }
            if (certs.length > 0) {
                this.x509Certificates = certs;
            }
        } catch (CertificateException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "parseError", e);
        }
    }

    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getX509Identifier(this.x509Certificates[0]);
        }
        return this.alias;
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return this.x509Certificates;
    }
}
