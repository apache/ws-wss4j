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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This test encrypts a Timestamp and the SOAP Body, and appends the ReferenceList Element after the
 * EncryptedData Element that is the Timestamp. When processing, the EncryptedData Element gets decrypted,
 * and then the ReferenceListProcessor must check to see whether the Data Reference pointing to the
 * encrypted Timestamp needs to be decrypted or not.
 */
public class EncryptedDataInHeaderTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(EncryptedDataInHeaderTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public EncryptedDataInHeaderTest() throws Exception {
        crypto = CryptoFactory.getInstance();
        WSSConfig.init();
    }

    @Test
    public void testEncryptedDataInHeader() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        timestamp.build(doc, secHeader);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        // Encrypt the Timestamp and SOAP Body
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        encrypt.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY, soapNamespace, "Content"
            );
        encrypt.getParts().add(encP);

        encrypt.prepare(doc, crypto);
        encrypt.prependToHeader(secHeader);

        // Append Reference List to security header
        Element refs = encrypt.encrypt();
        secHeader.getSecurityHeader().appendChild(refs);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(doc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
    }


    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verified and decrypted message:");
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
