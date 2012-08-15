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

package org.apache.ws.security.message;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * This is a test for signing the SOAP Body as well as the BinarySecurityToken that contains the certificate
 * used to verify the signature.
 */
public class SignedBSTTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignedBSTTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
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

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
