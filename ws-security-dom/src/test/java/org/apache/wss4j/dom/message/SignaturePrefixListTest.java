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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


/**
 * A test-case for WSS-626 - "Duplicates in the PrefixList".
 */
public class SignaturePrefixListTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignaturePrefixListTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SignaturePrefixListTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    @Test
    public void testDuplicatePrefixListValues() throws Exception {
        Document doc = null;
        try (InputStream inputStream =
            Loader.getResource("org/apache/wss4j/dom/message/SignaturePrefixListMessage.xml").openStream()) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            doc = builder.parse(inputStream);
        }

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document signedDoc = builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }
        WSHandlerResult results = verify(signedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        Element receivedSignature = (Element)actionResult.get(WSSecurityEngineResult.TAG_TOKEN_ELEMENT);
        assertNotNull(receivedSignature);

        // Check PrefixList
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("16c73ab6-b892-458f-abf5-2f875f74882e");
        XMLValidateContext context = new DOMValidateContext(crypto.getX509Certificates(cryptoType)[0].getPublicKey(), receivedSignature);
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature xmlSignature = signatureFactory.unmarshalXMLSignature(context);

        ExcC14NParameterSpec spec = (ExcC14NParameterSpec)xmlSignature.getSignedInfo().getCanonicalizationMethod().getParameterSpec();
        List<String> expectedPrefixes = new ArrayList<>(Arrays.asList("S12", "ds", "eb", "ebbp", "ns5"));
        assertEquals(expectedPrefixes, spec.getPrefixList());
    }

    private WSHandlerResult verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, null, crypto);
    }

}