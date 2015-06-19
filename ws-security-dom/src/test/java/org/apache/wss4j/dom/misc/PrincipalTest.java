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

package org.apache.wss4j.dom.misc;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.common.principal.UsernameTokenPrincipal;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.w3c.dom.Document;

/**
 * Test various principal objects after processing a security token.
 */
public class PrincipalTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(PrincipalTest.class);
    
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    /**
     * Test the principal that is created after processing a Username Token
     */
    @org.junit.Test
    public void testUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(signedDoc, null);
        
        Principal principal = 
            (Principal)results.getResults().get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof UsernameTokenPrincipal);
        assertTrue("wernerd".equals(principal.getName()));
        UsernameTokenPrincipal userPrincipal = (UsernameTokenPrincipal)principal;
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
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = 
            verify(signedDoc, new DummyValidator(), WSSecurityEngine.USERNAME_TOKEN, null);
        
        Principal principal = 
            (Principal)results.getResults().get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = verify(unsignedDoc, null);
        
        List<WSSecurityEngineResult> samlResults = 
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = verify(unsignedDoc, null);
        
        List<WSSecurityEngineResult> samlResults = 
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);
        
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = 
            verify(unsignedDoc, new DummyValidator(), WSSecurityEngine.SAML_TOKEN, null);
        
        List<WSSecurityEngineResult> samlResults = 
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = 
            verify(doc, new DummyValidator(), WSSecurityEngine.BINARY_TOKEN, crypto);
        
        List<WSSecurityEngineResult> bstResults = 
            results.getActionResults().get(WSConstants.BST);
        WSSecurityEngineResult actionResult = bstResults.get(0);

        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
    }
    
    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc,
        Crypto crypto
    ) throws Exception {
        return verify(doc, null, null, crypto);
    }
    
    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc, 
        Validator validator,
        QName validatorName,
        Crypto crypto
    ) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        requestData.setValidateSamlSubjectConfirmation(false);
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        secEngine.setWssConfig(config);
        
        if (validator != null && validatorName != null) {
            config.setValidator(validatorName, validator);
        }
        return secEngine.processSecurityHeader(doc, requestData);
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
                
                SAMLCallback samlCallback = new SAMLCallback();
                SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
                SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
    
                credential.setTransformedToken(samlAssertion);
                return credential;
            } catch (Exception ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
        }
        
    }
}
