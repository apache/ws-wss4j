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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

import java.util.Vector;

/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNew2 extends TestCase implements CallbackHandler {
    private static final Log LOG = LogFactory.getLog(TestWSSecurityNew2.class);
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
    private static final javax.xml.namespace.QName SOAP_BODY =
        new javax.xml.namespace.QName(
            WSConstants.URI_SOAP11_ENV,
            "Body"
        );

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance("wss40.properties");

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
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA_15 algorithm to transport (wrap) the symmetric
     * key.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    public void testEncryptionDecryptionRSA15() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        LOG.info("Before Encryption Triple DES....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        LOG.info("After Encryption Triple DES....");

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-15 keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("LogTestService2") == -1 ? true : false);
        verify(encryptedDoc, SOAP_BODY);

        /*
         * second run, same Junit set up, but change encryption method, 
         * key identification, encryption mode (Element now), and data to encrypt.
         * This tests if several runs of different algorithms on same builder/cipher 
         * setup are ok.
         */
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        java.util.List<WSEncryptionPart> parts = new Vector<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart("testMethod", "uri:LogTestService2", "Element");
        parts.add(encP);
        builder.setParts(parts);
        doc = SOAPUtil.toSOAPPart(SOAPMSG);
        secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        LOG.info("Before Encryption AES 128/RSA-15....");
        encryptedDoc = builder.build(doc, crypto, secHeader);
        LOG.info("After Encryption AES 128/RSA-15....");
        outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-15 keytransport, AES 128:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("LogTestService2") == -1 ? true : false);
        verify(
            encryptedDoc,
            new javax.xml.namespace.QName(
                "uri:LogTestService2",
                "testMethod"
            )
        );
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA OAEP algorithm to transport (wrap) the symmetric
     * key.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
     public void testEncryptionDecryptionOAEP() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        builder.setKeyEnc(WSConstants.KEYTRANSPORT_RSAOEP);
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        LOG.info("Before Encryption Triple DES/RSA-OAEP....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        LOG.info("After Encryption Triple DES/RSA-OAEP....");

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("LogTestService2") == -1 ? true : false);
        verify(encryptedDoc, SOAP_BODY);

    }
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    @SuppressWarnings("unchecked")
    private void verify(
        Document doc,
        javax.xml.namespace.QName expectedEncryptedElement
    ) throws Exception {
        final java.util.List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, this, null, crypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("LogTestService2") > 0 ? true : false);
        //
        // walk through the results, and make sure there is an encryption
        // action, together with a reference to the decrypted element 
        // (as a QName)
        //
        boolean encrypted = false;
        for (java.util.Iterator<WSSecurityEngineResult> ipos = results.iterator(); 
            ipos.hasNext();) {
            final WSSecurityEngineResult result = ipos.next();
            final Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            assertNotNull(action);
            if ((action.intValue() & WSConstants.ENCR) != 0) {
                final java.util.List<WSDataRef> refs =
                    (java.util.List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                assertNotNull(refs);
                encrypted = true;
                for (java.util.Iterator<WSDataRef> jpos = refs.iterator(); jpos.hasNext();) {
                    final WSDataRef ref = jpos.next();
                    assertNotNull(ref);
                    assertNotNull(ref.getName());
                    assertEquals(
                        expectedEncryptedElement,
                        ref.getName()
                    );
                    assertNotNull(ref.getProtectedElement());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("WSDataRef element: ");
                        LOG.debug(
                            org.apache.ws.security.util.DOM2Writer.nodeToString(
                                ref.getProtectedElement()
                            )
                        );
                    }
                }
            }
        }
        assertTrue(encrypted);
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
