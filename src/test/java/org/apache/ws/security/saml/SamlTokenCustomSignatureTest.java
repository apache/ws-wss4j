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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.validate.SamlAssertionValidator;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 */
public class SamlTokenCustomSignatureTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlTokenCustomSignatureTest.class);
    
    private Crypto crypto = null;
    
    public SamlTokenCustomSignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion.
     */
    @org.junit.Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_BEARER);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element assertionElement = assertion.toDOM(doc);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionElement);
        
        // Sign
        signAssertion(doc, assertionElement);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (Bearer):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        try {
            verify(doc);
            fail("Failure expected on a signature that doesn't conform with the signature profile");
        } catch (WSSecurityException ex) {
            // expected failure
        }
        
        // This should pass as we are disabling signature profile validation in the Validator
        verifyWithoutProfile(doc);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 2.0 authentication assertion.
     */
    @org.junit.Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element assertionElement = assertion.toDOM(doc);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionElement);
        
        // Sign
        signAssertion(doc, assertionElement);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2.0 Authn Assertion (Bearer):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        try {
            verify(doc);
            fail("Failure expected on a signature that doesn't conform with the signature profile");
        } catch (WSSecurityException ex) {
            // expected failure
        }
        
        // This should pass as we are disabling signature profile validation in the Validator
        verifyWithoutProfile(doc);
    }
    
    private void signAssertion(Document doc, Element assertionElement) throws Exception {
        XMLSignature sig = 
            new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA);
        assertionElement.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        String filter = "here()/ancestor::ds.Signature/parent::node()/descendant-or-self::*";
        XPath2FilterContainer xpathC = XPath2FilterContainer.newInstanceIntersect(doc, filter);
        xpathC.setXPathNamespaceContext("dsig-xpath", Transforms.TRANSFORM_XPATH2FILTER);
        
        Element node = xpathC.getElement();
        transforms.addTransform(Transforms.TRANSFORM_XPATH2FILTER, node);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        PrivateKey privateKey = crypto.getPrivateKey("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        sig.sign(privateKey);
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("16c73ab6-b892-458f-abf5-2f875f74882e");
        X509Certificate cert = crypto.getX509Certificates(cryptoType)[0];
        sig.addKeyInfo(cert);
        sig.checkSignatureValue(cert);
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(
                doc, null, null, crypto
            );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

    private List<WSSecurityEngineResult> verifyWithoutProfile(Document doc) throws Exception {
        SamlAssertionValidator validator = new SamlAssertionValidator();
        validator.setValidateSignatureAgainstProfile(false);
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = secEngine.getWssConfig();
        config.setValidator(WSSecurityEngine.SAML_TOKEN, validator);
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, validator);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(
                doc, null, null, crypto
            );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }


}
