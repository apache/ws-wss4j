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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.WSSecSignatureSAML;
import org.apache.ws.security.util.WSSecurityUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecHeader;

import org.w3c.dom.Document;

import org.opensaml.SAMLAssertion;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.List;

/**
 * Test-case for sending and processing a (signed) holder-of-key SAML Assertion.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNewST3 extends TestCase implements CallbackHandler {
    private static final Log LOG = LogFactory.getLog(TestWSSecurityNewST3.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +      "<ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance("crypto.properties");

    /**
     * TestWSSecurity constructor
     * 
     * @param name name of the test
     */
    public TestWSSecurityNewST3(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNewST3.class);
    }


    /**
     * * Test that creates, sends and processes an signed SAML assertion.
     */
    public void testSAMLSignedKeyHolder() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml4.properties");
        // Provide info to SAML issuer that it can construct a Holder-of-key
        // SAML token.
        saml.setInstanceDoc(doc);
        saml.setUserCrypto(crypto);
        saml.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        SAMLAssertion assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        LOG.info("Before SAMLSignedKeyHolder....");
        
        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        LOG.info("After SAMLSignedKeyHolder....");

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmlenc#sha256") != -1);
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") != -1);
        
        List results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    public void testSAMLSignedKeyHolderKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml4.properties");
        // Provide info to SAML issuer that it can construct a Holder-of-key
        // SAML token.
        saml.setInstanceDoc(doc);
        saml.setUserCrypto(crypto);
        saml.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        SAMLAssertion assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        LOG.info("Before SAMLSignedKeyHolder....");
        
        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        LOG.info("After SAMLSignedKeyHolder....");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }

    
    /**
     * Verifies the soap envelope
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List verify(Document doc) throws Exception {
        List results = secEngine.processSecurityHeader(doc, null, this, crypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("LogTestService2") > 0 ? true : false);
        return results;
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                /*
                 * here call a function/method to lookup the password for
                 * the given identifier (e.g. a user name or keystore alias)
                 * e.g.: pc.setPassword(passStore.getPassword(pc.getIdentfifier))
                 * for Testing we supply a fixed name here.
                 */
                pc.setPassword("security");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
