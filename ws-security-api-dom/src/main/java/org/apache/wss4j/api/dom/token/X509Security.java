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

package org.apache.wss4j.api.dom.token;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * X509 Security Token.
 */
public class X509Security extends BinarySecurity {

    public static final String X509_V3_TYPE = WSS4JConstants.X509TOKEN_NS + "#X509v3";

    /*
     * Stores the associated X.509 Certificate. This saves numerous
     * crypto loadCertificate operations
     */
    private X509Certificate cachedCert;

    /**
     * This constructor creates a new X509 certificate object and initializes
     * it from the data contained in the element.
     *
     * @param elem the element containing the X509 certificate data
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public X509Security(Element elem, BSPEnforcer bspEnforcer) throws WSSecurityException {
        super(elem, bspEnforcer);
        String valueType = getValueType();
        if (!X509_V3_TYPE.equals(valueType)) {
            bspEnforcer.handleBSPRule(BSPRule.R3033);
        }
    }

    /**
     * This constructor creates a new X509 certificate element.
     *
     * @param doc
     */
    public X509Security(Document doc) {
        super(doc);
        setValueType(X509_V3_TYPE);
    }

    /**
     * Gets the X509Certificate certificate.
     *
     * @return the X509 certificate converted from the base 64 encoded element data
     * @throws WSSecurityException
     */
    public X509Certificate getX509Certificate(Crypto crypto) throws WSSecurityException {
        if (cachedCert != null) {
            return cachedCert;
        }
        Crypto certCrypto = crypto;
        if (certCrypto == null) {
            certCrypto = new Merlin();
        }
        byte[] data = getToken();
        if (data == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "invalidCertData", new Object[] {"0"});
        }
        try (InputStream in = new ByteArrayInputStream(data)) {
            cachedCert = certCrypto.loadCertificate(in);
            return cachedCert;
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, e, "parseError"
            );
        }

    }

    /**
     * Sets the X509Certificate.
     * This functions takes the X509 certificate, gets the data from it as
     * encoded bytes, and sets the data as base 64 encoded data in the text
     * node of the element
     *
     * @param cert the X509 certificate to store in the element
     * @throws WSSecurityException
     */
    public void setX509Certificate(X509Certificate cert) throws WSSecurityException {
        if (cert == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCert");
        }
        cachedCert = cert;
        try {
            setToken(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, e, "encodeError"
            );
        }
    }
}
