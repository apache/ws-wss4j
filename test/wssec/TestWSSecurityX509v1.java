/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import java.util.Vector;

/**
 * WS-Security Test Case for X509v1 certificates. The WS-Security 1.1 X.509 specification adds 
 * support for X.509 V1 certificates. This test code verifies that the ValueType attribute gets 
 * set correctly in the BinarySecurityToken and Reference elements.
 */
public class TestWSSecurityX509v1 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurityX509v1.class);
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Body>" +
            "      <ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>" +
            "   </soapenv:Body>" +
            "</soapenv:Envelope>";

    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    static final Crypto v1Crypto = CryptoFactory.getInstance("x509v1.properties");
    MessageContext msgContext;
    SOAPEnvelope unsignedEnvelope;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityX509v1(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityX509v1.class);
    }

    /**
     * Main method
     * <p/>
     * 
     * @param args command line args
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * Setup method
     * <p/>
     * 
     * @throws Exception Thrown when there is a problem in setup
     */
    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
        unsignedEnvelope = getSOAPEnvelope();
    }

    /**
     * Constructs a soap envelope
     * <p/>
     * 
     * @return soap envelope
     * @throws java.lang.Exception if there is any problem constructing the soap envelope
     */
    protected SOAPEnvelope getSOAPEnvelope() throws Exception {
        InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg.getSOAPEnvelope();
    }

    /**
     * Test for a X509 V1 certificate used for signature/verification.
     */
    public void testX509v1Signature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("x509v1cert", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, v1Crypto, secHeader);
        
        if (log.isDebugEnabled()) {
            log.debug("Signed message with BST_DIRECT_REFERENCE:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            log.debug(outputString);
            assertTrue(outputString.indexOf("#X509v1") != -1);
            assertTrue(outputString.indexOf("#X509v3") == -1);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Test for a X509 V1 certificate used for encryption/decryption
     */
    public void testX509v1Encryption() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("x509v1cert");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document encryptedDoc = builder.build(doc, v1Crypto, secHeader);
        
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message with BST_DIRECT_REFERENCE:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            log.debug(outputString);
            assertTrue(outputString.indexOf("#X509v1") != -1);
            assertTrue(outputString.indexOf("#X509v3") == -1);
        }
        
        verify(encryptedDoc);
    }
    
    /**
     * Test for a X509 V1 certificate used for encryption/decryption.
     * This time a KeyIdentifier is used. This test should fail as the
     * X.509 1.1 specification states that a KeyIdentifer should only
     * reference a V3 certificate.
     */
    public void testX509v1KeyIdentifier() throws Exception {
        try {
            WSSecEncrypt builder = new WSSecEncrypt();
            builder.setUserInfo("x509v1cert");
            builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
            Document doc = unsignedEnvelope.getAsDocument();
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);        
            Document encryptedDoc = builder.build(doc, v1Crypto, secHeader);
            fail("Expected failure when using an X509#v1 certificate with SKI");
        } catch (WSSecurityException ex) {
            // expected
            assertTrue(ex.getMessage().indexOf(
                "An X509 certificate with version 3 must be used for SKI")
                != -1
            );
        }
    }
    
    
    /**
     * Verifies the soap envelope.
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, v1Crypto);
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
