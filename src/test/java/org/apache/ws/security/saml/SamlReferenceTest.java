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

package org.apache.ws.security.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;
import java.util.ArrayList;

import javax.security.auth.callback.CallbackHandler;

/**
 * Some tests for how SAML tokens are referenced.
 */
public class SamlReferenceTest extends org.junit.Assert {
    private static final Log LOG = LogFactory.getLog(SamlReferenceTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();

    /**
     * The body of the SOAP request is encrypted using a secret key, which is in turn encrypted
     * using the certificate embedded in the SAML assertion and referenced using a Key Identifier.
     * This test checks that KeyIdentifier (and not Reference) elements are used to identify 
     * SAML tokens
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testSAMLEncryptedKey() throws Exception {
        // Create a SAML assertion
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Crypto hokCrypto = CryptoFactory.getInstance("crypto.properties");
        AssertionWrapper assertion = saml.newAssertion();
        Node assertionNode = assertion.toDOM(doc);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionNode);
        
        // Encrypt the SOAP body
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        builder.setCustomEKTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        builder.setCustomEKTokenId(assertion.getId());
        
        builder.prepare(doc, hokCrypto);
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);
        Element refElement = builder.encryptForRef(null, parts);
        builder.addInternalRefElement(refElement);
        builder.appendToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (HOK):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc, hokCrypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * WS-Security Test Case for WSS-178 - "signature verification failure of signed saml token
     * due to "The Reference for URI (bst-saml-uri) has no XMLSignatureInput".
     * 
     * The problem is that the signature is referring to a SecurityTokenReference via the 
     * STRTransform, which in turn is referring to the SAML Assertion. The request is putting 
     * the SAML Assertion below the SecurityTokenReference, and this is causing 
     * SecurityTokenReference.getTokenElement to fail.
     */
    @org.junit.Test
    public void testKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();
        Crypto crypto = CryptoFactory.getInstance("crypto.properties");
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        Document samlDoc = 
            wsSign.build(doc, null, assertion, crypto, 
                "16c73ab6-b892-458f-abf5-2f875f74882e", "security", secHeader
            );
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document encryptedDoc = builder.build(samlDoc, crypto, secHeader);
        
        //
        // Remove the assertion its place in the security header and then append it
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Node assertionNode = 
            secHeaderElement.getElementsByTagNameNS(WSConstants.SAML_NS, "Assertion").item(0);
        secHeaderElement.removeChild(assertionNode);
        secHeaderElement.appendChild(assertionNode);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message:");
            LOG.debug(outputString);
        }
        
        verify(encryptedDoc, crypto);
    }
    
    /**
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    @org.junit.Test
    public void testSAMLSignedSenderVouchesKeyIdentifier() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        
        LOG.info("Before SAMLSignedSenderVouches....");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto crypto = CryptoFactory.getInstance("crypto.properties");
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );
        LOG.info("After SAMLSignedSenderVouches....");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc, crypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc, Crypto verifyCrypto) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, verifyCrypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }
    
}
