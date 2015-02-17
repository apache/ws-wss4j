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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.token.X509Security;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * This is a test for signing the SOAP Body as well as the BinarySecurityToken that contains the certificate
 * used to verify the signature.
 */
public class SignedBSTTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignedBSTTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SignedBSTTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     */
    @org.junit.Test
    public void testSignedBST() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        // Get a certificate, convert it into a BinarySecurityToken and add it to the security header
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertNotNull(certs);
        
        X509Security bst = new X509Security(doc);
        String certUri = WSSConfig.getNewInstance().getIdAllocator().createSecureId("X509-", certs[0]);
        bst.setX509Certificate(certs[0]);
        bst.setID(certUri);
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        // Add the signature
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setSignatureAlgorithm(WSConstants.RSA);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setX509Certificate(certs[0]);

        List<WSEncryptionPart> parts = new ArrayList<>();
        // Add SOAP Body
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY, soapNamespace, "Content"
            );
        parts.add(encP);
        // Add BST
        encP =
            new WSEncryptionPart(
                WSConstants.BINARY_TOKEN_LN, WSConstants.WSSE_NS, "Element"
            );
        encP.setElement(bst.getElement());
        parts.add(encP);
        sign.setParts(parts);
        
        sign.setCustomTokenId(bst.getID());
        sign.setCustomTokenValueType(bst.getValueType());
        sign.prepare(doc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            sign.addReferencesToSign(parts, secHeader);
        sign.computeSignature(referenceList, false, null);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    @org.junit.Test
    public void testSignedBSTAction() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put("password", "security");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, 
            "{}{" + WSConstants.WSSE_NS + "}BinarySecurityToken"
        );
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        assertTrue(handler.checkResults(results, Collections.singletonList(WSConstants.SIGN)));
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
