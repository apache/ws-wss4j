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

package org.apache.wss4j.dom.message;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.List;

/**
 * A set of test-cases for encrypting and decrypting SOAP requests using GCM. See:
 * https://issues.apache.org/jira/browse/WSS-325
 */
public class EncryptionGCMTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(EncryptionGCMTest.class);
    private static final javax.xml.namespace.QName SOAP_BODY =
        new javax.xml.namespace.QName(
            WSConstants.URI_SOAP11_ENV,
            "Body"
        );

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler keystoreCallbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public EncryptionGCMTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }
    
    /**
     * Setup method
     * 
     * @throws java.lang.Exception Thrown when there is a problem in setup
     */
    @org.junit.Before
    public void setUp() throws Exception {
        secEngine.setWssConfig(WSSConfig.getNewInstance());
    }
    
    @org.junit.Test
    public void testAES128GCM() throws Exception {
        //
        // This test fails with the IBM JDK 7
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))
            && System.getProperty("java.version") != null
            &&  System.getProperty("java.version").startsWith("1.7")) {
            return;
        }
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128_GCM);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("counter_port_type") == -1 ? true : false);
        verify(encryptedDoc, keystoreCallbackHandler, SOAP_BODY);
    }
    
    @org.junit.Test
    public void testAES256GCM() throws Exception {
        //
        // This test fails with the IBM JDK 7
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))
            && System.getProperty("java.version") != null
            &&  System.getProperty("java.version").startsWith("1.7")) {
            return;
        }
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_256_GCM);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("counter_port_type") == -1 ? true : false);
        verify(encryptedDoc, keystoreCallbackHandler, SOAP_BODY);
    }

    @org.junit.Test
    public void testAES192GCM_RSAOAEP_SHA256_MGFSHA256() throws Exception {
        //
        // This test fails with the IBM JDK 7
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))
            && System.getProperty("java.version") != null
            &&  System.getProperty("java.version").startsWith("1.7")) {
            return;
        }

        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_192_GCM);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOEP_XENC11);
        builder.setDigestAlgorithm(WSConstants.SHA256);
        builder.setMGFAlgorithm(WSConstants.MGF_SHA256);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        String outputString =
                XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("http://www.w3.org/2009/xmlenc11#rsa-oaep") > 0);
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmlenc#sha256") > 0);
        assertTrue(outputString.indexOf("http://www.w3.org/2009/xmlenc11#aes192-gcm") > 0);
        assertTrue(outputString.indexOf("http://www.w3.org/2009/xmlenc11#mgf1sha256") > 0);
        assertTrue(outputString.indexOf("counter_port_type") == -1 ? true : false);
        verify(encryptedDoc, keystoreCallbackHandler, SOAP_BODY);
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @throws Exception Thrown when there is a problem in verification
     */
    @SuppressWarnings("unchecked")
    private void verify(
        Document doc,
        CallbackHandler handler,
        javax.xml.namespace.QName expectedEncryptedElement
    ) throws Exception {
        RequestData requestData = new RequestData();
        List<BSPRule> bspRules = new ArrayList<BSPRule>();
        bspRules.add(BSPRule.R5621);
        requestData.setIgnoredBSPRules(bspRules);
        requestData.setCallbackHandler(handler);
        requestData.setDecCrypto(crypto);
        final java.util.List<WSSecurityEngineResult> results =
            secEngine.processSecurityHeader(doc, null, requestData);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
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
                            DOM2Writer.nodeToString(ref.getProtectedElement())
                        );
                    }
                }
            }
        }
        assertTrue(encrypted);
    }

}
