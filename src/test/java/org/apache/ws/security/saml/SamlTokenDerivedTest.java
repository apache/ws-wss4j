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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

/**
 * Test-case for sending and processing a signed (sender vouches) SAML Assertion using a 
 * derived key.
 */
public class SamlTokenDerivedTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlTokenDerivedTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public SamlTokenDerivedTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion
     * using a derived key.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertionDerived() throws Exception {
        //
        // Create a SAML Assertion + STR, and add both to the security header
        //
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SecurityTokenReference secRefSaml = 
            createSamlSTR(doc, assertion, WSSConfig.getNewInstance());
        secHeader.getSecurityHeader().appendChild(assertion.toDOM(doc));
        secHeader.getSecurityHeader().appendChild(secRefSaml.getElement());
        
        //
        // Create a Derived Key object for signature
        //
        WSSecDKSign sigBuilder = createDKSign(doc, secRefSaml);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion Derived (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml1:Assertion", xpath);
    }
    
    /**
     * Create a SecurityTokenReference to a SAML Assertion
     */
    private SecurityTokenReference createSamlSTR(
        Document doc, 
        AssertionWrapper assertion,
        WSSConfig wssConfig
    ) {
        SecurityTokenReference secRefSaml = new SecurityTokenReference(doc);
        String secRefID = wssConfig.getIdAllocator().createSecureId("STRSAMLId-", secRefSaml);
        secRefSaml.setID(secRefID);

        org.apache.ws.security.message.token.Reference ref = 
            new org.apache.ws.security.message.token.Reference(doc);
        ref.setURI("#" + assertion.getId());
        ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        secRefSaml.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
        secRefSaml.setReference(ref);
        
        return secRefSaml;
    }
    
    /**
     * Create a WSSecDKSign object, that signs the SOAP Body as well as the SAML Assertion
     * via a STR Transform.
     */
    private WSSecDKSign createDKSign(
        Document doc,
        SecurityTokenReference secRefSaml
    ) throws WSSecurityException {
        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("16c73ab6-b892-458f-abf5-2f875f74882e");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierThumb(certs[0]);
        
        WSSecDKSign sigBuilder = new WSSecDKSign();
        java.security.Key key = 
            crypto.getPrivateKey("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>(2);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace, 
                "Content"
            );
        parts.add(encP);
        encP = new WSEncryptionPart("STRTransform", "", "Element");
        encP.setId(secRefSaml.getID());
        encP.setElement(secRefSaml.getElement());
        parts.add(encP);
        sigBuilder.setParts(parts);
        
        return sigBuilder;
    }
   
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
