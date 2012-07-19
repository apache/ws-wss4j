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

import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.EncodedPasswordCallbackHandler;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.List;

/**
 * WS-Security Test Case for UsernameTokens.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class UsernameTokenTest extends org.junit.Assert implements CallbackHandler {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(UsernameTokenTest.class);
    private static final String SOAPUTMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "<wsse:UsernameToken wsu:Id=\"UsernameToken-29477163\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        + "<wsse:Username>wernerd</wsse:Username>"
        + "<wsse:Password>verySecret</wsse:Password>"
        + "</wsse:UsernameToken></wsse:Security></SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    private static final String SOAPUTNOUSERMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "<wsse:UsernameToken wsu:Id=\"UsernameToken-29477163\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        + "<wsse:Username></wsse:Username>"
        + "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\"></wsse:Password>"
        + "</wsse:UsernameToken></wsse:Security></SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    private static final String EMPTY_PASSWORD_MSG =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "<wsse:UsernameToken wsu:Id=\"UsernameToken-1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
        + "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        + "<wsse:Username>emptyuser</wsse:Username>"
        + "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\"/>"
        + "</wsse:UsernameToken></wsse:Security></SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    /**
     * Test that adds a UserNameToken with password Digest to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenDigest() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        LOG.info("Before adding UsernameToken PW Digest....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Digest....");
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT);
        UsernameToken receivedToken = 
            (UsernameToken) actionResult.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
        assertTrue(receivedToken != null);
        
        UsernameToken clone = new UsernameToken(receivedToken.getElement());
        assertTrue(clone.equals(receivedToken));
        assertTrue(clone.hashCode() == receivedToken.hashCode());
    }
    
    /**
     * Test for encoded passwords.
     */
    @org.junit.Test
    public void testUsernameTokenWithEncodedPasswordBaseline() throws Exception {
        String password = "password";
        // The SHA-1 of the password is known as a password equivalent in the UsernameToken specification.
        byte[] passwordHash = MessageDigest.getInstance("SHA-1").digest(password.getBytes("UTF-8"));

        String nonce = "0x7bXAPZVn40AdCD0Xbt0g==";
        String created = "2010-06-28T15:16:37Z";
        String expectedPasswordDigest = "C0rena/6gKpRZ9ATj+e6ss5sAbQ=";
        String actualPasswordDigest = UsernameToken.doPasswordDigest(nonce, created, passwordHash);
        assertEquals("the password digest is not as expected", expectedPasswordDigest, actualPasswordDigest);
    }
    
    /**
     * Test that adds a UserNameToken with password Digest to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenWithEncodedPassword() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordsAreEncoded(true);
        builder.setUserInfo("wernerd", Base64.encode(MessageDigest.getInstance("SHA-1").digest("verySecret".getBytes("UTF-8"))));
        LOG.info("Before adding UsernameToken PW Digest....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Digest....");

        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.getWssConfig().setPasswordsAreEncoded(true);
        newEngine.processSecurityHeader(signedDoc, null, new EncodedPasswordCallbackHandler(), null);
    }
    
    /**
     * Test that a bad username with password digest does not leak whether the username
     * is valid or not - see WSS-141.
     */
    @org.junit.Test
    public void testUsernameTokenBadUsername() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("badusername", "verySecret");
        LOG.info("Before adding UsernameToken PW Digest....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Digest....");
        try {
            verify(signedDoc);
            fail("Failure expected on a bad username");
        } catch (WSSecurityException ex) {
            String message = ex.getMessage();
            assertTrue(message.indexOf("badusername") == -1);
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test that adds a UserNameToken with a bad password Digest to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenBadDigest() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecre");
        LOG.info("Before adding UsernameToken PW Digest....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Digest....");
        try {
            verify(signedDoc);
            fail("Failure expected on a bad password digest");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }

    /**
     * Test that adds a UserNameToken with password text to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenText() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecret");
        LOG.info("Before adding UsernameToken PW Text....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Text:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Text....");

        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT);
        UsernameToken receivedToken = 
            (UsernameToken) actionResult.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
        assertTrue(receivedToken != null);
        
        UsernameToken clone = new UsernameToken(receivedToken.getElement());
        assertTrue(clone.equals(receivedToken));
        assertTrue(clone.hashCode() == receivedToken.hashCode());
    }
    
    /**
     * Test that adds a UserNameToken with a digested password but with type of
     * password test.
     */
    @org.junit.Test
    public void testUsernameTokenDigestText() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        byte[] password = "verySecret".getBytes();
        MessageDigest sha = MessageDigest.getInstance("MD5");
        sha.reset();
        sha.update(password);
        String passwdDigest = Base64.encode(sha.digest());
        
        builder.setUserInfo("wernerd", passwdDigest);
        LOG.info("Before adding UsernameToken PW Text....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Text:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * Test that adds a UserNameToken with (bad) password text to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenBadText() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecre");
        LOG.info("Before adding UsernameToken PW Text....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Text:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Text....");
        
        try {
            verify(signedDoc);
            fail("Failure expected on a bad password text");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test that adds a UserNameToken with no password type to a WS-Security envelope
     * See WSS-152 - https://issues.apache.org/jira/browse/WSS-152
     * "Problem with processing Username Tokens with no password type"
     * The 1.1 spec states that the password type is optional and defaults to password text, 
     * and so we should handle an incoming Username Token accordingly.
     */
    @org.junit.Test
    public void testUsernameTokenNoPasswordType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTMSG);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("Expected failure as it is not BSP compliant");
        } catch (WSSecurityException ex) {
            // expected
        }
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * Test that adds a UserNameToken with no user (or password) to a WS-Security envelope
     * See WSS-185 - https://issues.apache.org/jira/browse/WSS-185
     * "NullPointerException on empty UsernameToken"
     */
    @org.junit.Test
    public void testUsernameTokenNoUser() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTNOUSERMSG);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        try {
            verify(doc);
            fail("Failure expected on no password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test that adds a UserNameToken with no password
     */
    @org.junit.Test
    public void testUsernameTokenNoPassword() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(null);
        builder.setUserInfo("nopassuser", null);
        LOG.info("Before adding UsernameToken with no password....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_NOPASSWORD);
        UsernameToken receivedToken = 
            (UsernameToken) actionResult.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
        assertTrue(receivedToken != null);
    }
    
    /**
     * Test that adds a UserNameToken with an empty password
     */
    @org.junit.Test
    public void testUsernameTokenEmptyPassword() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("emptyuser", "");
        LOG.info("Before adding UsernameToken with an empty password....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        secEngine.processSecurityHeader(doc, null, this, null);
    }
    
    /**
     * Test that processes a UserNameToken with an empty password
     */
    @org.junit.Test
    public void testEmptyPasswordProcessing() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(EMPTY_PASSWORD_MSG);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Empty password message: ");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        secEngine.processSecurityHeader(doc, null, this, null);
    }
    
    /**
     * Test with a non-standard token type. This will fail as the default is to reject custom
     * token types.
     */
    @org.junit.Test
    public void testUsernameTokenCustomFail() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType("RandomType");
        builder.setUserInfo("wernerd", "verySecret");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Text:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        try {
            secEngine.processSecurityHeader(signedDoc, null, this, null);
            fail("Custom token types are not permitted");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test with a non-standard password type. This will pass as the WSSConfig is configured to 
     * handle custom token types.
     */
    @org.junit.Test
    public void testUsernameTokenCustomPass() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType("RandomType");
        builder.setUserInfo("wernerd", "verySecret");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW custom type:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Configure so that custom token types are accepted
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        cfg.setHandleCustomPasswordTypes(true);
        secEngine.setWssConfig(cfg);
        verify(signedDoc);
        
        //
        // Go back to default for other tests
        //
        cfg.setHandleCustomPasswordTypes(false);
        secEngine.setWssConfig(cfg);
    }
    
    
    /**
     * A test for WSS-66 - the nonce string is null
     * http://issues.apache.org/jira/browse/WSS-66
     * "Possible security hole when PasswordDigest is used by client."
     */
    @org.junit.Test
    public void testNullNonce() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "BAD_PASSWORD");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Nonce node and set the content to null
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSSE_NS, "Nonce");
        org.w3c.dom.Node nonceNode = list.item(0);
        org.w3c.dom.Node childNode = nonceNode.getFirstChild();
        childNode.setNodeValue("");
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        try {
            //
            // Verification should fail as the password is bad
            //
            verify(utDoc);
            fail("Expected failure due to a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * A test for WSS-66 - the created string is null
     * http://issues.apache.org/jira/browse/WSS-66
     * "Possible security hole when PasswordDigest is used by client."
     */
    @org.junit.Test
    public void testNullCreated() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "BAD_PASSWORD");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Created node and set the content to null
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSU_NS, "Created");
        org.w3c.dom.Node nonceNode = list.item(0);
        org.w3c.dom.Node childNode = nonceNode.getFirstChild();
        childNode.setNodeValue("");
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        try {
            //
            // Verification should fail as the password is bad
            //
            verify(utDoc);
            fail("Expected failure due to a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test that verifies an EncodingType is set for the nonce. See WSS-169.
     */
    @org.junit.Test
    public void testUsernameTokenNonceEncodingType() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        LOG.info("Before adding UsernameToken PW Digest....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.indexOf("EncodingType") != -1);
    }
    
    /**
     * Test that adds a UserNameToken via WSHandler
     */
    @org.junit.Test
    public void testUsernameTokenWSHandler() throws Exception {
        CustomHandler handler = new CustomHandler();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        RequestData reqData = new RequestData();
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put("password", "verySecret");
        config.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
        reqData.setUsername("wernerd");
        reqData.setMsgContext(config);
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        
        handler.send(WSConstants.UT, doc, reqData, actions, true);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Username Token via WSHandler");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * Test that adds a UserNameToken with no password via WSHandler
     */
    @org.junit.Test
    public void testUsernameTokenWSHandlerNoPassword() throws Exception {
        CustomHandler handler = new CustomHandler();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        RequestData reqData = new RequestData();
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_NONE);
        reqData.setUsername("wernerd");
        reqData.setMsgContext(config);
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        
        handler.send(WSConstants.UT, doc, reqData, actions, true);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Username Token via WSHandler");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * Test that adds a UserNameToken with an empty password via WSHandler
     */
    @org.junit.Test
    public void testUsernameTokenWSHandlerEmptyPassword() throws Exception {
        CustomHandler handler = new CustomHandler();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        RequestData reqData = new RequestData();
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
        config.put(WSHandlerConstants.PW_CALLBACK_REF, this);
        reqData.setUsername("emptyuser");
        reqData.setMsgContext(config);
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        
        handler.send(WSConstants.UT, doc, reqData, actions, true);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Username Token with an empty password via WSHandler");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for sending multiple nonces in the UsernameToken
     */
    @org.junit.Test
    public void testMultipleNonce() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "verySecret");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Nonce node and duplicate it
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSSE_NS, "Nonce");
        org.w3c.dom.Node nonceNode = list.item(0);
        org.w3c.dom.Node nonceCopy = nonceNode.cloneNode(true);
        nonceNode.getParentNode().insertBefore(nonceCopy, nonceNode);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("Expected failure as it is not BSP compliant");
        } catch (WSSecurityException ex) {
            // expected
        }
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * A test for sending multiple Created elements in the UsernameToken
     */
    @org.junit.Test
    public void testMultipleCreated() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "verySecret");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Created node and duplicate it
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSU_NS, "Created");
        org.w3c.dom.Node createdNode = list.item(0);
        org.w3c.dom.Node createdCopy = createdNode.cloneNode(true);
        createdNode.getParentNode().insertBefore(createdCopy, createdNode);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("Expected failure as it is not BSP compliant");
        } catch (WSSecurityException ex) {
            // expected
        }
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * A test for sending multiple passwords in the UsernameToken
     */
    @org.junit.Test
    public void testMultiplePassword() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "verySecret");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Nonce node and duplicate it
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSSE_NS, "Password");
        org.w3c.dom.Node passwordNode = list.item(0);
        org.w3c.dom.Node passwordCopy = passwordNode.cloneNode(true);
        passwordNode.getParentNode().insertBefore(passwordCopy, passwordNode);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("Expected failure as it is not BSP compliant");
        } catch (WSSecurityException ex) {
            // expected
        }
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * A test for sending a nonce with a bad encoding type in the UsernameToken
     */
    @org.junit.Test
    public void testNonceBadEncodingType() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "verySecret");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document utDoc = builder.build(doc, secHeader);
        
        //
        // Manually find the Nonce node and duplicate it
        //
        org.w3c.dom.Element elem = builder.getUsernameTokenElement();
        org.w3c.dom.NodeList list = elem.getElementsByTagNameNS(WSConstants.WSSE_NS, "Nonce");
        org.w3c.dom.Node nonceNode = list.item(0);
        ((org.w3c.dom.Element)nonceNode).setAttributeNS(
            null, "EncodingType", "http://bad_encoding_type"
        );
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(utDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("Expected failure as it is not BSP compliant");
        } catch (WSSecurityException ex) {
            // expected
        }
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * A CallbackHandler for some (mostly insecure) scenarios.
     */
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                if (pc.getUsage() == WSPasswordCallback.USERNAME_TOKEN) {
                    if ("emptyuser".equals(pc.getIdentifier())) {
                        pc.setPassword("");
                    } else if ("customUser".equals(pc.getIdentifier())) {
                        return;
                    } else if (null == pc.getIdentifier()) {
                        // Note that this is not secure! Just doing this to test a NPE
                        return;
                    }
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
