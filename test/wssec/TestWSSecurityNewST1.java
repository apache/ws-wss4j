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

import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.saml.SAMLIssuer;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.w3c.dom.Document;

import org.opensaml.SAMLAssertion;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNewST1 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurityNewST1.class);
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Body>" +
            "      <ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>" +
            "   </soapenv:Body>" +
            "</soapenv:Envelope>";

    static final WSSecurityEngine secEngine = new WSSecurityEngine();

    // static final Crypto crypto = CryptoFactory.getInstance("crypto.properties");
    MessageContext msgContext;
    Message message;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityNewST1(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNewST1.class);
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
    public void testSAMLUnsignedSenderVouches() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml.properties");

        SAMLAssertion assertion = saml.newAssertion();

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        log.info("Before SAMLUnsignedSenderVouches....");
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);
        log.info("After SAMLUnsignedSenderVouches....");

        /*
         * convert the resulting document into a message first. The toAxisMessage()
         * method performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. Check that the contents can't
          * be read (cheching if we can find a specific substring). After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Unsigned SAML message (sender vouches):");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        // String encryptedString = signedMsg.getSOAPPartAsString();
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        verify(signedDoc);

    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, null);
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
