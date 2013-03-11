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

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.xml.security.binding.xmldsig.X509DataType;
import org.apache.xml.security.binding.xmldsig.X509IssuerSerialType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.impl.util.UnsynchronizedByteArrayInputStream;

import javax.security.auth.callback.CallbackHandler;
import java.security.cert.X509Certificate;

public class X509DataSecurityToken extends X509SecurityToken {

    private String alias = null;
    private final X509DataType x509DataType;

    X509DataSecurityToken(WSSecurityContext wsSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
                          X509DataType x509DataType, String id, WSSConstants.KeyIdentifierType keyIdentifierType,
                          WSSSecurityProperties securityProperties) {
        super(WSSConstants.X509V3Token, wsSecurityContext, crypto, callbackHandler, id, keyIdentifierType, securityProperties);
        this.x509DataType = x509DataType;
    }

    @Override
    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null) {
            X509IssuerSerialType x509IssuerSerialType = XMLSecurityUtils.getQNameType(
                    x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(), WSSConstants.TAG_dsig_X509IssuerSerial);
            if (x509IssuerSerialType != null) {
                if (x509IssuerSerialType.getX509IssuerName() == null
                        || x509IssuerSerialType.getX509SerialNumber() == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                }
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
                cryptoType.setIssuerSerial(
                        x509IssuerSerialType.getX509IssuerName(), x509IssuerSerialType.getX509SerialNumber()
                );
                X509Certificate[] certs = getCrypto().getX509Certificates(cryptoType);
                setX509Certificates(certs);
                if (certs == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                }
                return this.alias = getCrypto().getX509Identifier(certs[0]);
            }
            byte[] x509CertificateBytes = XMLSecurityUtils.getQNameType(
                    x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(), WSSConstants.TAG_dsig_X509Certificate);
            if (x509CertificateBytes != null) {
                X509Certificate[] certs =
                        new X509Certificate[]{
                                getCrypto().loadCertificate(
                                        new UnsynchronizedByteArrayInputStream(x509CertificateBytes))
                        };
                setX509Certificates(certs);
                return this.alias = getCrypto().getX509Identifier(certs[0]);
            }
        }
        return this.alias;
    }
}
