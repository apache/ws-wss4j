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

import java.util.List;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;


/**
 * A set of test-cases for signing and verifying SOAP requests using the Merlin AKI Crypto implementation.
 */
public class SignatureAKITest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureAKITest.class);
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SignatureAKITest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40CAAKI.properties");
    }

    @org.junit.Test
    public void testSignatureAKI() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto signingCrypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = builder.build(doc, signingCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
    }
    
    /**
     * Verifies the soap envelope.
     * This method verifies all the signature generated. 
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, null, crypto);
    }

}
