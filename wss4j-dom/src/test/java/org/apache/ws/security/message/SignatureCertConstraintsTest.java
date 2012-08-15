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

package org.apache.ws.security.message;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * A set of test-cases for signing and verifying SOAP requests, where the certificate used to
 * verify the signature is validated against a set of cert constraints.
 */
public class SignatureCertConstraintsTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureCertConstraintsTest.class);
    private Crypto crypto = null;
    private Crypto cryptoCA = null;
    
    public SignatureCertConstraintsTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
        cryptoCA = CryptoFactory.getInstance("wss40CA.properties");
    }

    /**
     * The test uses the BinarySecurityToken key identifier type.
     */
    @org.junit.Test
    public void testBSTSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with BST key identifier:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        String certConstraint = ".*CN=Colm.*O=Apache.*";
        verify(securityHeader, cryptoCA, certConstraint);
        
        certConstraint = ".*CN=Colm2.*O=Apache.*";
        try {
            verify(securityHeader, cryptoCA, certConstraint);
            fail("Failure expected on a bad cert constraint");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * The test uses the BinarySecurityToken key identifier type.
     */
    @org.junit.Test
    public void testBSTSignaturePKIPath() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setUseSingleCertificate(false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with BST key identifier:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        String certConstraint = ".*CN=Colm.*O=Apache.*";
        verify(securityHeader, cryptoCA, certConstraint);
        
        certConstraint = ".*CN=Colm2.*O=Apache.*";
        try {
            verify(securityHeader, cryptoCA, certConstraint);
            fail("Failure expected on a bad cert constraint");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    private List<WSSecurityEngineResult> verify(
        Element securityHeader, Crypto sigCrypto, String certConstraint
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigCrypto(sigCrypto);
        
        if (certConstraint != null) {
            Pattern subjectDNPattern = Pattern.compile(certConstraint.trim());
            data.setSubjectCertConstraints(Collections.singletonList(subjectDNPattern));
        }
        
        return secEngine.processSecurityHeader(securityHeader, data);
    }

}
