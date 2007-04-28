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
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import org.apache.xml.security.signature.XMLSignature;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;


/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class TestWSSecurityNew12 extends TestCase {
    private static Log log = LogFactory.getLog(TestWSSecurityNew12.class);
    static final String NS = "http://www.w3.org/2000/09/xmldsig#";
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" + "<SOAP-ENV:Body>" + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" + "<value xmlns=\"\">15</value>" + "</add>" + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    static final Crypto crypto = CryptoFactory.getInstance("cryptoSKI.properties");

    MessageContext msgContext;
    SOAPEnvelope unsignedEnvelope;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityNew12(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNew12.class);
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
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. It
     * uses the Direct version, that is it embedds the certificate in the message.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureDSA_SKI() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcertDSA", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        builder.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_DSA);
        
        // builder.setUserInfo("john", "keypass");
        log.info("Before SigningDSA_SKIDirect....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        /*
         * convert the resulting document into a message first. The toAxisMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with DSA_SKI key identifier:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }

        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After SigningDSA_SKIDirect....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. 
     * It gets a certificate with a DSA public key algo to sign, WSSignEnvelope shall
     * detect the algo and set the signature algo accordingly.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureDSA_Autodetect() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcertDSA", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        
        // builder.setUserInfo("john", "keypass");
        log.info("Before SigningDSA_Autodetect....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        /*
         * convert the resulting document into a message first. The toAxisMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with DSA_Autodetect:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }

        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After SigningDSA_Autodetect....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope using SubjectKeyIdentifier.
     * This test uses the SubjectKeyIdentifier to identify the certificate. 
     * It gets a certificate with a RSA public key algo to sign, WSSignEnvelope shall
     * detect the algo and set the signature algo accordingly.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureRSA_Autodetect() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcert", "security");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        
        // builder.setUserInfo("john", "keypass");
        log.info("Before SigningRSA_Autodetect....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        /*
         * convert the resulting document into a message first. The toAxisMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with RSA Autodetect:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }

        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After SigningRSA_Autodetect....");
        verify(signedDoc);
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, null, crypto);
    }
}
