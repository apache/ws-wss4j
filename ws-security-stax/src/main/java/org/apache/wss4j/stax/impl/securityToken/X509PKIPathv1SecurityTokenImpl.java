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
package org.apache.wss4j.stax.impl.securityToken;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;

public class X509PKIPathv1SecurityTokenImpl extends X509SecurityTokenImpl {

    private String alias;

    public X509PKIPathv1SecurityTokenImpl(
            WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
            byte[] binaryContent, String id, WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
            WSSSecurityProperties securityProperties) throws XMLSecurityException {

        super(WSSecurityTokenConstants.X509PkiPathV1Token, wsInboundSecurityContext, crypto,
                callbackHandler, id, keyIdentifier, securityProperties, true);

        try (InputStream in = new UnsyncByteArrayInputStream(binaryContent)) {
            CertPath certPath = getCrypto().getCertificateFactory().generateCertPath(in);
            List<? extends Certificate> l = certPath.getCertificates();
            X509Certificate[] certs = new X509Certificate[l.size()];
            Iterator<? extends Certificate> iterator = l.iterator();
            for (int i = 0; i < l.size(); i++) {
                certs[i] = (X509Certificate) iterator.next();
            }
            if (certs.length > 0) {
                setX509Certificates(certs);
            }
        } catch (CertificateException | IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e, "parseError");
        }
    }

    @Override
    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null && getCrypto() != null) {
            this.alias = getCrypto().getX509Identifier(getX509Certificates()[0]);
        }
        return this.alias;
    }
}
