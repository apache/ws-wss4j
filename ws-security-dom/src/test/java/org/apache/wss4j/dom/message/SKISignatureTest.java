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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.str.STRParser.REFERENCE_TYPE;
import org.w3c.dom.Document;

/**
 * WS-Security Test Case for SubjectKeyIdentifier.
 */
public class SKISignatureTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SKISignatureTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SKISignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. It
     * uses the Direct version, that is it embeds the certificate in the message.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureDSA_SKI() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40DSA", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        builder.setSignatureAlgorithm(WSConstants.DSA);
        
        LOG.info("Before SigningDSA_SKIDirect....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with DSA_SKI key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After SigningDSA_SKIDirect....");
        
        WSHandlerResult results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.KEY_IDENTIFIER);
    }

    /**
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. 
     * It gets a certificate with a DSA public key algo to sign, WSSignEnvelope shall
     * detect the algo and set the signature algo accordingly.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureDSA_Autodetect() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40DSA", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        
        LOG.info("Before SigningDSA_Autodetect....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with DSA_Autodetect:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After SigningDSA_Autodetect....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. 
     * It gets a certificate with a RSA public key algo to sign, WSSignEnvelope shall
     * detect the algo and set the signature algo accordingly.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureRSA_Autodetect() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        
        LOG.info("Before SigningRSA_Autodetect....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with RSA Autodetect:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After SigningRSA_Autodetect....");
        verify(signedDoc);
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, null, crypto);
    }
}
