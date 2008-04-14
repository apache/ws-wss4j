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
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * WS-Security Test Case for using the ThumbprintSHA1 key identifier for
 * signature and encryption, and the EncryptedKeySHA1 key identifier for encryption.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNew14 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurityNew14.class);
    static final String NS = "http://www.w3.org/2000/09/xmldsig#";
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" + "<SOAP-ENV:Body>" + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" + "<value xmlns=\"\">15</value>" + "</add>" + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    static final Crypto crypto = CryptoFactory.getInstance();

    MessageContext msgContext;
    SOAPEnvelope unsignedEnvelope;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityNew14(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNew14.class);
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
     * @throws java.lang.Exception Thrown when there is a problem in setup
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
     * Test that signs and verifies a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type. 
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureThumb() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        // builder.setUserInfo("john", "keypass");
        log.info("Before Signing ThumbprintSHA1....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        /*
         * convert the resulting document into a message first. The toAxisMessage()
         * method performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with ThumbprintSHA1 key identifier:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing ThumbprintSHA1....");
        verify(signedDoc);
    }

    /**
     * Test that signs (twice) and verifies a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testDoubleX509SignatureThumb() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        // builder.setUserInfo("john", "keypass");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);        
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);
        Document signedDoc1 = builder.build(signedDoc, crypto, secHeader);
        verify(signedDoc1);
    }
    
    /**
     * Test that encrypts and decrypts a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type. 
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    public void testX509EncryptionThumb() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        
        log.info("Before Encrypting ThumbprintSHA1....");
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message with THUMBPRINT_IDENTIFIER:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            log.debug(outputString);
            assertTrue(outputString.indexOf("#ThumbprintSHA1") != -1);
        }
    
        log.info("After Encrypting ThumbprintSHA1....");
        verify(encryptedDoc);
    }
        
    /**
     * Test that encrypts and decrypts a WS-Security envelope.
     * The test uses the EncryptedKeySHA1 key identifier type. 
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    public void testX509EncryptionSHA1() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
     
        log.info("Before Encrypting EncryptedKeySHA1....");
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
     
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message with ENCRYPTED_KEY_SHA1_IDENTIFIER:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            log.debug(outputString);
            assertTrue(outputString.indexOf("#EncryptedKeySHA1") != -1);
        }
     
        log.info("After Encrypting EncryptedKeySHA1....");
        verify(encryptedDoc);
    }

    /**
     * Verifies the soap envelope.
     * This method verfies all the signature generated. 
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, crypto);
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
