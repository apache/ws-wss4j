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

package org.apache.wss4j.dom.message;

import java.util.Collections;
import java.util.regex.Pattern;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;

import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * A set of test-cases for signing and verifying SOAP requests, where the issuer of the certificate used to
 * verify the signature is validated against a set of cert constraints.
 */
public class SignatureIssuerCertConstraintsTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureIssuerCertConstraintsTest.class);
    private Crypto crypto;
    private Crypto cryptoCA;

    public SignatureIssuerCertConstraintsTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
        cryptoCA = CryptoFactory.getInstance("wss40CA.properties");
    }

    /**
     * The test uses the BinarySecurityToken key identifier type.
     */
    @Test
    public void testBSTSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with BST key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        String certConstraint = ".*CN=Werner.*OU=Apache.*";
        verify(securityHeader, cryptoCA, certConstraint);

        certConstraint = ".*CN=Werner2.*O=Apache.*";
        try {
            verify(securityHeader, cryptoCA, certConstraint);
            fail("Failure expected on a bad cert constraint");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

    /**
     * The test uses the BinarySecurityToken key identifier type.
     */
    @Test
    public void testBSTSignaturePKIPath() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setUseSingleCertificate(false);

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with BST key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        String certConstraint = ".*CN=Werner.*OU=Apache.*";
        verify(securityHeader, cryptoCA, certConstraint);

        certConstraint = ".*CN=Werner2.*O=Apache.*";
        try {
            verify(securityHeader, cryptoCA, certConstraint);
            fail("Failure expected on a bad cert constraint");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

    private WSHandlerResult verify(
        Element securityHeader, Crypto sigCrypto, String certConstraint
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigVerCrypto(sigCrypto);

        if (certConstraint != null) {
            Pattern issuerDNPattern = Pattern.compile(certConstraint.trim());
            data.setIssuerDNPatterns(Collections.singletonList(issuerDNPattern));
        }

        return secEngine.processSecurityHeader(securityHeader, data);
    }

}