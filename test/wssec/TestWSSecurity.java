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
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSignEnvelope;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;


/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurity extends TestCase {
    private static Log log = LogFactory.getLog(TestWSSecurity.class);
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
    public TestWSSecurity(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurity.class);
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
     * The test uses the IssuerSerial key identifier type. 
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureIS() throws Exception {
        SOAPEnvelope envelope = null;
        WSSignEnvelope builder = new WSSignEnvelope();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        // builder.setUserInfo("john", "keypass");
        log.info("Before Signing IS....");
        Document doc = unsignedEnvelope.getAsDocument();
        Document signedDoc = builder.build(doc, crypto);

        /*
         * convert the resulting document into a message first. The toSOAPMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = (Message) AxisUtil.toSOAPMessage(signedDoc);
        if (log.isDebugEnabled()) {
        	log.debug("Signed message with IssuerSerial key identifier:");
			XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing IS....");
        verify(signedDoc);
    }

	/**
	 * Test that signs and verifies a WS-Security envelope.
	 * The test uses the IssuerSerialDirect key identifier type. With
	 * this key identifier the signing functions inserts the certificate
	 * into the message.  
	 * <p/>
	 * TODO: use another certificate that is not stored in the keystore.
	 * 
	 * @throws java.lang.Exception Thrown when there is any problem in signing or verification
	 */
//	public void testX509SignatureISDirect() throws Exception {
//		SOAPEnvelope envelope = null;
//		WSSignEnvelope builder = new WSSignEnvelope();
//		builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
//		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL_DIRECT);
//		// builder.setUserInfo("john", "keypass");
//		log.info("Before Signing ISDirect....");
//		Document doc = unsignedEnvelope.getAsDocument();
//		Document signedDoc = builder.build(doc, crypto);
//
//		Message signedMsg = (Message) AxisUtil.toSOAPMessage(signedDoc);
//		if (log.isDebugEnabled()) {
//			log.debug("Signed message with IssuerSerialDirect key identifier:");
//			XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
//		}
//		signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
//		log.info("After Signing ISDirect....");
//		verify(signedDoc);
//	}

    /**
     * Test that signs (twice) and verifies a WS-Security envelope.
     * The test uses the IssuerSerial key identifier type.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testDoubleX509SignatureIS() throws Exception {
        SOAPEnvelope envelope = null;
        WSSignEnvelope builder = new WSSignEnvelope();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        // builder.setUserInfo("john", "keypass");
        Document doc = unsignedEnvelope.getAsDocument();
        Document signedDoc = builder.build(doc, crypto);
        Document signedDoc1 = builder.build(signedDoc, crypto);
        verify(signedDoc1);
    }

    /**
     * Verifies the soap envelope.
     * This method verfies all the signature generated. 
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, null, crypto);
    }
}
