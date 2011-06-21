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

package org.apache.ws.security.misc;

import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Test various principal objects after processing a security token.
 */
public class PrincipalTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(PrincipalTest.class);
    
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    /**
     * Test the principal that is created after processing a Username Token
     */
    @org.junit.Test
    public void testUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = verify(signedDoc, null);
        
        Principal principal = (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof WSUsernameTokenPrincipal);
        assertTrue("wernerd".equals(principal.getName()));
        WSUsernameTokenPrincipal userPrincipal = (WSUsernameTokenPrincipal)principal;
        assertTrue(userPrincipal.getCreatedTime() != null);
        assertTrue(userPrincipal.getNonce() != null);
        assertTrue(userPrincipal.getPassword() != null);
        assertTrue(userPrincipal.isPasswordDigest());
        assertTrue(WSConstants.PASSWORD_DIGEST.equals(userPrincipal.getPasswordType()));
    }
    
    /**
     * Test the principal that is created after processing a Username Token, which has been
     * transformed into a SAML Assertion.
     */
    @org.junit.Test
    public void testTransformedUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = 
            verify(signedDoc, new DummyValidator(), WSSecurityEngine.USERNAME_TOKEN, null);
        
        Principal principal = (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Test the principal that is created after processing a SAML Token
     */
    @org.junit.Test
    public void testSAMLToken() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        Principal principal = 
            (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Test the principal that is created after processing a SAML2 Token
     */
    @org.junit.Test
    public void testSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        Principal principal = 
            (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Test the principal that is created after processing a SAML Token, which has been
     * transformed into another SAML Token.
     */
    @org.junit.Test
    public void testTransformedSAMLToken() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = 
            verify(unsignedDoc, new DummyValidator(), WSSecurityEngine.SAML_TOKEN, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        Principal principal = 
            (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Test the principal that is created after processing (and explicitly validating)
     * a BinarySecurityToken.
     */
    @org.junit.Test
    public void testBinarySecurityToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = 
            verify(doc, new DummyValidator(), WSSecurityEngine.BINARY_TOKEN, crypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
        
        Principal principal = 
            (Principal)results.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Verifies the soap envelope
     */
    private List<WSSecurityEngineResult> verify(
        Document doc,
        Crypto crypto
    ) throws Exception {
        return verify(doc, null, null, crypto);
    }
    
    /**
     * Verifies the soap envelope
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, 
        Validator validator,
        QName validatorName,
        Crypto crypto
    ) throws Exception {
        WSSConfig config = WSSConfig.getNewInstance();
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        if (validator != null && validatorName != null) {
            config.setValidator(validatorName, validator);
        }
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }
    
    /**
     * A Dummy Validator instance that just creates a new SAML Assertion, ignoring the
     * credential it has been passed.
     */
    private static class DummyValidator implements Validator {

        public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
            try {
                SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
                callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
                callbackHandler.setIssuer("www.example.com");
                
                SAMLParms samlParms = new SAMLParms();
                samlParms.setCallbackHandler(callbackHandler);
                AssertionWrapper assertion = new AssertionWrapper(samlParms);
    
                credential.setTransformedToken(assertion);
                return credential;
            } catch (Exception ex) {
                throw new WSSecurityException(WSSecurityException.FAILURE);
            }
        }
        
    }
}
