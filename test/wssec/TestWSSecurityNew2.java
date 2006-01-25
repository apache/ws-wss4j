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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import java.util.Vector;

/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNew2 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurityNew2.class);
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Body>" +
            "      <ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>" +
            "   </soapenv:Body>" +
            "</soapenv:Envelope>";

    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    static final Crypto crypto = CryptoFactory.getInstance("cryptoSKI.properties");
    MessageContext msgContext;
    Message message;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityNew2(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNew2.class);
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
        message = getSOAPMessage();
    }

    /**
     * Constructs a soap envelope
     * <p/>
     * 
     * @return soap envelope
     * @throws Exception if there is any problem constructing the soap envelope
     */
    protected Message getSOAPMessage() throws Exception {
        InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg;
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA_15 alogrithm to transport (wrap) the symmetric
     * key.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    public void testEncryptionDecryptionRSA15() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        SOAPEnvelope envelope = null;
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss4jcert");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        log.info("Before Encryption Triple DES....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        log.info("After Encryption Triple DES....");

        /*
         * convert the resulting document into a message first. The toSOAPMessage()
         * method performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. Check that the contents can't
          * be read (cheching if we can find a specific substring). After that we extract it
         * as a document again for further processing.
         */

        Message encryptedMsg = (Message) SOAPUtil.toSOAPMessage(encryptedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message, RSA-15 keytransport, 3DES:");
            XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        String encryptedString = encryptedMsg.getSOAPPartAsString();
        assertTrue(encryptedString.indexOf("LogTestService2") == -1 ? true : false);
        encryptedDoc = encryptedMsg.getSOAPEnvelope().getAsDocument();
        verify(encryptedDoc);

        /*
         * second run, same Junit set up, but change encryption method, 
         * key identification, encryption mode (Element now), and data to encrypt.
         * This tests if several runs of different algorithms on same builder/cipher 
         * setup are ok.
         */
        message = getSOAPMessage(); // create fresh message envrionment
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        Vector parts = new Vector();
        WSEncryptionPart encP =
            new WSEncryptionPart("testMethod", "uri:LogTestService2", "Element");
        parts.add(encP);
        builder.setParts(parts);
        unsignedEnvelope = message.getSOAPEnvelope();
        doc = unsignedEnvelope.getAsDocument();
        secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        log.info("Before Encryption AES 128/RSA-15....");
        encryptedDoc = builder.build(doc, crypto, secHeader);
        log.info("After Encryption AES 128/RSA-15....");
        encryptedMsg = (Message) SOAPUtil.toSOAPMessage(encryptedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message, RSA-15 keytransport, AES 128:");
            XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        encryptedString = encryptedMsg.getSOAPPartAsString();
        assertTrue(encryptedString.indexOf("LogTestService2") == -1 ? true : false);
        encryptedDoc = encryptedMsg.getSOAPEnvelope().getAsDocument();
        verify(encryptedDoc);
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA OAEP alogrithm to transport (wrap) the symmetric
     * key.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
     public void testEncryptionDecryptionOAEP() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        SOAPEnvelope envelope = null;
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss4jcert");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        builder.setKeyEnc(WSConstants.KEYTRANSPORT_RSAOEP);
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        log.info("Before Encryption Triple DES/RSA-OAEP....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        log.info("After Encryption Triple DES/RSA-OAEP....");

        Message encryptedMsg = (Message) SOAPUtil.toSOAPMessage(encryptedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        String encryptedString = encryptedMsg.getSOAPPartAsString();
        assertTrue(encryptedString.indexOf("LogTestService2") == -1 ? true : false);
        encryptedDoc = encryptedMsg.getSOAPEnvelope().getAsDocument();
        verify(encryptedDoc);

    }
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, crypto);
        SOAPUtil.updateSOAPMessage(doc, message);
        String decryptedString = message.getSOAPPartAsString();
        assertTrue(decryptedString.indexOf("LogTestService2") > 0 ? true : false);
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
