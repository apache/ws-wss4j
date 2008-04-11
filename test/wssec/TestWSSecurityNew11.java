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
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Vector;

/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNew11 extends TestCase {
    private static Log log = LogFactory.getLog(TestWSSecurityNew11.class);
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
    public TestWSSecurityNew11(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNew11.class);
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
     * This test uses the direct reference key identifier (certificate included
     * as a BinarySecurityToken (BST) in the message). The test signs the message
     * body (SOAP Body) and uses the STRTransform to sign the embedded certificate
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testX509SignatureDirectSTR() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcert", "security");
        // builder.setUserInfo("john", "keypass");
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(unsignedEnvelope.getAsDOM());
        Vector parts = new Vector();
        
        /*
         * Set up to sign body and use STRTransorm to sign
         * the signature token (e.g. X.509 certificate)
         */
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        builder.setParts(parts);
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        log.info("Before Signing STR DirectReference....");
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
            log.debug("Signed message with STR DirectReference key identifier:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing STR DirectReference....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the IssuerSerialDirect reference key identifier (certificate included
     * as a BinarySecurityToken (BST) in the message) but identified with IssuerSerialNumber
     * and <b>not</b> with a Reference (relative URI). The test signs the message
     * body (SOAP Body) and uses the STRTransform to sign the embedded certificate
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
//    public void testX509SignatureISDirectSTR() throws Exception {
//        SOAPEnvelope envelope = null;
//        WSSignEnvelope builder = new WSSignEnvelope();
//        builder.setUserInfo("wss4jcert", "security");
//        // builder.setUserInfo("john", "keypass");
//        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(unsignedEnvelope);
//        Vector parts = new Vector();
//        
//        /*
//         * Set up to sign body and use STRTransorm to sign
//         * the signature token (e.g. X.509 certificate)
//         */
//        WSEncryptionPart encP =
//            new WSEncryptionPart(
//                soapConstants.getBodyQName().getLocalPart(),    // define the body
//                soapConstants.getEnvelopeURI(),
//                "Content");
//        parts.add(encP);
//        encP =
//            new WSEncryptionPart(
//                "STRTransform",                // reserved word to use STRTransform
//                soapConstants.getEnvelopeURI(),
//                "Content");
//        parts.add(encP);
//
//        builder.setParts(parts);
//        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL_DIRECT);
//
//        log.info("Before Signing STR ISDirect....");
//        Document doc = unsignedEnvelope.getAsDocument();
//        Document signedDoc = builder.build(doc, crypto);
//
//        Message signedMsg = (Message) SOAPUtil.toSOAPMessage(signedDoc);
//        if (log.isDebugEnabled()) {
//            log.debug("Signed message with STR IssuerSerialDirect key identifier:");
//            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
//        }
//        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
//        log.info("After Signing STR ISDirect....");
//        verify(signedDoc);
//    }

    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the IssuerSerial reference key identifier (certificate not included
     * in the message)and reads the certificate from a keystore using IssuerSerialNumber
     * to identify it.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    

    public void testX509SignatureISSTR() throws Exception {
        SOAPEnvelope envelope = null;
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcert", "security");
        // builder.setUserInfo("john", "keypass");
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(unsignedEnvelope.getAsDOM());
        Vector parts = new Vector();
        
        /*
         * Set up to sign body and use STRTransorm to sign
         * the signature token (e.g. X.509 certificate)
         */
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",                // reserved word to use STRTransform
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        builder.setParts(parts);
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        log.info("Before Signing STR IS....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        Message signedMsg = (Message) SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with STR IssuerSerial key identifier:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing STR IS....");
        verify(signedDoc);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the SubjectKeyIdentifier key identifier (certificate not included
     * in the message) and reads the certificate from a keystore using SKI
     * to identify it.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    

    public void testX509SignatureSKISTR() throws Exception {
        SOAPEnvelope envelope = null;
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss4jcert", "security");
        // builder.setUserInfo("john", "keypass");
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(unsignedEnvelope.getAsDOM());
        Vector parts = new Vector();
        
        /*
         * Set up to sign body and use STRTransorm to sign
         * the signature token (e.g. X.509 certificate)
         */
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);
        encP =
            new WSEncryptionPart(
                "STRTransform",                // reserved word to use STRTransform
                soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        builder.setParts(parts);
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);

        log.info("Before Signing STR SKI....");
        Document doc = unsignedEnvelope.getAsDocument();
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        Message signedMsg = (Message) SOAPUtil.toAxisMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with STR SKI key identifier:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing STR SKI....");
        verify(signedDoc);
    }

    /**
     * Test that signs and verifies a WS-Security envelope.
     * This test uses the SubjectKeyIdentifierDirect key identifier (certificate included
     * in the message).
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    

//    public void testX509SignatureSKIDirectSTR() throws Exception {
//        SOAPEnvelope envelope = null;
//        WSSignEnvelope builder = new WSSignEnvelope();
//        builder.setUserInfo("wss4jcert", "security");
//        // builder.setUserInfo("john", "keypass");
//        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(unsignedEnvelope);
//        Vector parts = new Vector();
//        
//        /*
//         * Set up to sign body and use STRTransorm to sign
//         * the signature token (e.g. X.509 certificate)
//         */
//        WSEncryptionPart encP =
//            new WSEncryptionPart(
//                soapConstants.getBodyQName().getLocalPart(),    // define the body
//                soapConstants.getEnvelopeURI(),
//                "Content");
//        parts.add(encP);
//        encP =
//            new WSEncryptionPart(
//                "STRTransform",                // reserved word to use STRTransform
//                soapConstants.getEnvelopeURI(),
//                "Content");
//        parts.add(encP);
//
//        builder.setParts(parts);
//        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER_DIRECT);
//
//        log.info("Before Signing STR SKIDirect....");
//        Document doc = unsignedEnvelope.getAsDocument();
//        Document signedDoc = builder.build(doc, crypto);
//
//        Message signedMsg = (Message) SOAPUtil.toSOAPMessage(signedDoc);
//        if (log.isDebugEnabled()) {
//            log.debug("Signed message with STR SKIDirect key identifier:");
//            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
//        }
//        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
//        log.info("After Signing STR SKIDirect....");
//        verify(signedDoc);
//    }


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
