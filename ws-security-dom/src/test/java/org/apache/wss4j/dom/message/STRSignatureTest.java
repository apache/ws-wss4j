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

import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.XMLUtils;
import org.w3c.dom.Document;

/**
 * WS-Security Test Case for signature creation/validation using the
 * SecurityTokenReference transform.
 */
public class STRSignatureTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(STRSignatureTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public STRSignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the direct reference key identifier (certificate included
     * as a BinarySecurityToken (BST) in the message). The test signs the message
     * body (SOAP Body) and uses the STRTransform to sign the embedded certificate
     * <p/>
     *
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testX509SignatureDirectSTR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");

        //
        // Set up to sign body and use STRTransform to sign
        // the signature token (e.g. X.509 certificate)
        //
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);

        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        LOG.info("Before Signing STR DirectReference....");

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with STR DirectReference key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing STR DirectReference....");
        verify(signedDoc);
    }

    /**
     * This is a test for WSS-96:
     * "Error when making a signature when containing a WSSecTimestamp"
     * A timestamp is added to the document and signed.
     */
    @Test
    public void testWSS96() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");

        //
        // Set up to sign body and use STRTransform to sign
        // the signature token (e.g. X.509 certificate)
        //
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(600);
        timestamp.build();
        builder.getParts().add(new WSEncryptionPart(timestamp.getId()));

        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        LOG.info("Before Signing STR DirectReference....");
        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with STR DirectReference key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing STR DirectReference....");
        verify(signedDoc);
    }


    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the IssuerSerial reference key identifier (certificate not included
     * in the message)and reads the certificate from a keystore using IssuerSerialNumber
     * to identify it.
     * <p/>
     *
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testX509SignatureISSTR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");

        //
        // Set up to sign body and use STRTransform to sign
        // the signature token (e.g. X.509 certificate)
        //
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",                // reserved word to use STRTransform
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);

        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        LOG.info("Before Signing STR IS....");

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with STR IssuerSerial key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing STR IS....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the SubjectKeyIdentifier key identifier (certificate not included
     * in the message) and reads the certificate from a keystore using SKI
     * to identify it.
     * <p/>
     *
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testX509SignatureSKISTR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");

        //
        // Set up to sign body and use STRTransform to sign
        // the signature token (e.g. X.509 certificate)
        //
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",                // reserved word to use STRTransform
                soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);

        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);

        LOG.info("Before Signing STR SKI....");

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with STR SKI key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing STR SKI....");
        verify(signedDoc);
    }


    /**
     * Verifies the soap envelope
     *
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, null, crypto);
    }
}
