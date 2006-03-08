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


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecDKEncrypt;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;

public class TestWSSecurityNewDK extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurityNewDK.class);
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
    public TestWSSecurityNewDK(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNewDK.class);
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
     * Test encryption using a DerivedKeyToken using TRIPLEDES
     * @throws Exception Thrown when there is any problem in signing or 
     * verification
     */
    public void testEncryptionDecryptionTRIPLEDES() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setEncryptionUser("wss4jcert");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.build(doc, crypto, secHeader);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokneIdentifier = encrKeyBuilder.getTokneIdentifier();  
        
        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokneIdentifier);
        Document encryptedDoc = encrBuilder.build(doc, crypto, secHeader);
        
        encrKeyBuilder.commit(encryptedDoc, crypto, secHeader);
        
       Message encryptedMsg = (Message) SOAPUtil.toSOAPMessage(encryptedDoc);
       if (log.isDebugEnabled()) {
           log.debug("Encrypted message: 3DES  + DerivedKeys");
           XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope()
                    .getAsDOM(), new PrintWriter(System.out));
       }
//       String out = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
//       System.out.println(out);
       verify(doc);
    }

    /**
     * Test encryption using a DerivedKeyToken using AES128 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
     public void testEncryptionDecryptionAES128() throws Exception {
         SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
         Document doc = unsignedEnvelope.getAsDocument();
         WSSecHeader secHeader = new WSSecHeader();
         secHeader.insertSecurityHeader(doc);

         //EncryptedKey
         WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
         encrKeyBuilder.setEncryptionUser("wss4jcert");
         encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
         encrKeyBuilder.build(doc, crypto, secHeader);

         //Key information from the EncryptedKey
         byte[] ek = encrKeyBuilder.getEphemeralKey();
         String tokneIdentifier = encrKeyBuilder.getTokneIdentifier();  
         
         //Derived key encryption
         WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
         encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
         encrBuilder.setExternalKey(ek, tokneIdentifier);
         Document encryptedDoc = encrBuilder.build(doc, crypto, secHeader);
         
         encrKeyBuilder.commit(encryptedDoc, crypto, secHeader);
         
        Message encryptedMsg = (Message) SOAPUtil.toSOAPMessage(encryptedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Encrypted message: 3DES  + DerivedKeys");
            XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope()
                    .getAsDOM(), new PrintWriter(System.out));
        }
//        String out = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
//        System.out.println(out);
        verify(doc);
     }
     
     public void testSignature() throws Exception {
         SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
         Document doc = unsignedEnvelope.getAsDocument();
         WSSecHeader secHeader = new WSSecHeader();
         secHeader.insertSecurityHeader(doc);

         //EncryptedKey
         WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
         encrKeyBuilder.setEncryptionUser("wss4jcert");
         encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
         encrKeyBuilder.build(doc, crypto, secHeader);

         //Key information from the EncryptedKey
         byte[] ek = encrKeyBuilder.getEphemeralKey();
         String tokneIdentifier = encrKeyBuilder.getTokneIdentifier();         
         
         //Derived key encryption
         WSSecDKSign sigBuilder = new WSSecDKSign();
         sigBuilder.setExternalKey(ek, tokneIdentifier);
         sigBuilder.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
         Document signedDoc = sigBuilder.build(doc, crypto, secHeader);
         
         encrKeyBuilder.commit(signedDoc, crypto, secHeader);
         
         Message signedMessage = (Message) SOAPUtil.toSOAPMessage(doc);
         if (log.isDebugEnabled()) {
             log.debug("Encrypted message: 3DES  + DerivedKeys");
             XMLUtils.PrettyElementToWriter(signedMessage.getSOAPEnvelope()
                    .getAsDOM(), new PrintWriter(System.out));
         }
//         String out = org.apache.ws.security.util.XMLUtils
//                .PrettyDocumentToString(signedDoc);
//        System.out.println(out);
         verify(doc);
     }
     
     public void testSignatureEncrypt() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setEncryptionUser("wss4jcert");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.build(doc, crypto, secHeader);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokneIdentifier = encrKeyBuilder.getTokneIdentifier();

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ek, tokneIdentifier);
        sigBuilder.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        log.info("Before HMAC-SHA1 signature");
        Document signedDoc = sigBuilder.build(doc, crypto, secHeader);

        //Derived key signature
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokneIdentifier);
        Document signedEncryptedDoc = encrBuilder.build(signedDoc, crypto,
                secHeader);

        encrKeyBuilder.commit(signedEncryptedDoc, crypto, secHeader);

        Message signedMessage = (Message) SOAPUtil
                .toSOAPMessage(signedEncryptedDoc);

        if (log.isDebugEnabled()) {
            log.debug("Encrypted message: 3DES  + DerivedKeys");
            XMLUtils.PrettyElementToWriter(signedMessage.getSOAPEnvelope()
                    .getAsDOM(), new PrintWriter(System.out));
        }
//        String out = org.apache.ws.security.util.XMLUtils
//                .PrettyDocumentToString(signedEncryptedDoc);
//        System.out.println(out);
        verify(signedEncryptedDoc);
    }
     
     public void testEncryptSignature() throws Exception {
         SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
         Document doc = unsignedEnvelope.getAsDocument();
         WSSecHeader secHeader = new WSSecHeader();
         secHeader.insertSecurityHeader(doc);

         //EncryptedKey
         WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
         encrKeyBuilder.setEncryptionUser("wss4jcert");
         encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
         encrKeyBuilder.build(doc, crypto, secHeader);
         
         //Key information from the EncryptedKey
         byte[] ek = encrKeyBuilder.getEphemeralKey();
         String tokneIdentifier = encrKeyBuilder.getTokneIdentifier();
         
         //Derived key encryption
         WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
         encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
         encrBuilder.setExternalKey(ek, tokneIdentifier);
         Document encryptedDoc = encrBuilder.build(doc, crypto, secHeader);
         
         //Derived key signature
         WSSecDKSign sigBuilder = new WSSecDKSign();
         sigBuilder.setExternalKey(ek, tokneIdentifier);
         sigBuilder.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
         log.info("Before HMAC-SHA1 signature");
         Document encryptedSignedDoc = sigBuilder.build(encryptedDoc, crypto,
                secHeader);
         
         encrKeyBuilder.commit(encryptedSignedDoc, crypto, secHeader);
         
         Message signedMessage = (Message) SOAPUtil
                .toSOAPMessage(encryptedSignedDoc);
         
         if (log.isDebugEnabled()) {
            log.debug("Encrypted message: 3DES  + DerivedKeys");
            XMLUtils.PrettyElementToWriter(signedMessage.getSOAPEnvelope()
                    .getAsDOM(), new PrintWriter(System.out));
        }
        
//         String out = org.apache.ws.security.util.XMLUtils
//                .PrettyDocumentToString(encryptedSignedDoc);
//         System.out.println(out);
         verify(encryptedSignedDoc);
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
                throw new UnsupportedCallbackException(callbacks[i],
                        "Unrecognized Callback");
            }
        }
    }
}
