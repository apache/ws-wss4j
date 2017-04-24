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
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConfigurationException;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;

import javax.security.auth.callback.CallbackHandler;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

public class X509V3SecurityTokenImpl extends X509SecurityTokenImpl {

    private String alias;

    public X509V3SecurityTokenImpl(
            WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
            byte[] binaryContent, String id, WSSSecurityProperties securityProperties) throws XMLSecurityException {

        super(WSSecurityTokenConstants.X509V3Token, wsInboundSecurityContext, crypto, callbackHandler, id,
                WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier, securityProperties, true);

        try (InputStream inputStream = new UnsyncByteArrayInputStream(binaryContent)) {
            X509Certificate x509Certificate = getCrypto().loadCertificate(inputStream);
            setX509Certificates(new X509Certificate[]{x509Certificate});
        } catch (IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e, "parseError");
        }

        // Check to see if the certificates actually correspond to the decryption crypto
        if (getCrypto().getX509Identifier(getX509Certificates()[0]) == null) {
            try {
                Crypto decCrypto = securityProperties.getDecryptionCrypto();
                if (decCrypto != null
                        && decCrypto != getCrypto()
                        && decCrypto.getX509Identifier(getX509Certificates()[0]) != null) {
                    setCrypto(decCrypto);
                }
            } catch (WSSConfigurationException ex) { //NOPMD
                // Just continue
            }
        }
    }

    @Override
    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getX509Identifier(getX509Certificates()[0]);
        }
        return this.alias;
    }
}
