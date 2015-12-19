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

package org.apache.wss4j.dom.processor;

import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
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
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Test that checks for correct WSDataRef which should be returned by
 * <code>org.apache.wss4j.dom.processor.ReferenceListProcessor</code>
 *
 * This test uses the RSA_15 algorithm to transport (wrap) the symmetric key.
 * The test case creates a ReferenceList element that references EncryptedData
 * elements. The ReferencesList element is put into the Security header, not
 * as child of the EncryptedKey. The EncryptedData elements contain a KeyInfo
 * that references the EncryptedKey via a STR/Reference structure.
 *
 * WSDataRef object must contain the correct QName of the decrypted element.
 *
 */
public class ReferenceListDataRefTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ReferenceListDataRefTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public ReferenceListDataRefTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig.init();
    }

    /**
     * Test that check for correct WSDataRef object from ReferenceList Processor
     *
     *
     * @throws Exception
     *             Thrown when there is an error in encryption or decryption
     */
    @Test
    public void testDataRefReferenceListProcessor() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES....");

        /*
         * Prepare the Encrypt object with the token, setup data structure
         */
        builder.prepare(doc, crypto);

        /*
         * Set up the parts structure to encrypt the body
         */
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        builder.getParts().add(encP);

        /*
         * Encrypt the element (testMethod), create EncryptedData elements that reference
         * the EncryptedKey, and get a ReferenceList that can be put into the
         * Security header. Be sure that the ReferenceList is after the
         * EncryptedKey element in the Security header (strict layout)
         */
        Element refs = builder.encrypt();
        builder.addExternalRefElement(refs, secHeader);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        builder.prependToHeader(secHeader);

        builder.prependBSTElementToHeader(secHeader);

        Document encryptedDoc = doc;
        LOG.info("After Encryption Triple DES....");

        checkDataRef(encryptedDoc);
    }

    /**
     * Verifies the soap envelope <p/>
     *
     * @param envelope
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    @SuppressWarnings("unchecked")
    private void checkDataRef(Document doc) throws Exception {

        // Retrieve the wsResults List
        WSHandlerResult wsResults =
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        boolean found = false;

        for (int i = 0; i < wsResults.getResults().size(); i++) {
            WSSecurityEngineResult wsSecEngineResult = wsResults.getResults().get(i);
            int action = (Integer)
                    wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);

            // We want to filter only encryption results
            if (action != WSConstants.ENCR) {
                continue;
            }
            List<WSDataRef> dataRefs =
                (List<WSDataRef>)wsSecEngineResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

            //We want check only the DATA_REF_URIS
            if (dataRefs != null && dataRefs.size() > 0) {
                for (int j = 0; j < dataRefs.size(); j++) {
                    Object obj = dataRefs.get(i);

                    // ReferenceList Processor must Return a WSDataRef objects
                    assertTrue(obj instanceof WSDataRef);

                    WSDataRef dataRef = (WSDataRef) obj;

                    // Check whether QName is correctly set
                    assertEquals("add", dataRef.getName().getLocalPart());
                    assertEquals(
                        "http://ws.apache.org/counter/counter_port_type",
                        dataRef.getName().getNamespaceURI()
                    );

                    // Check whether wsu:Id is set
                    assertNotNull(dataRef.getWsuId());

                    // Check the encryption algorithm was set
                    assertEquals(WSConstants.TRIPLE_DES, dataRef.getAlgorithm());

                    // flag to indicate the element was found in TAG_DATA_REF_URIS
                    found = true;

                }
            }
        }

        // Make sure the element is actually found in the decrypted elements
        assertTrue(found);

    }

}
