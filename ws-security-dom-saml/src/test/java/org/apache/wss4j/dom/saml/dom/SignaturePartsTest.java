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

package org.apache.wss4j.dom.saml.dom;

import org.apache.wss4j.api.dom.WSEncryptionPart;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.api.dom.WSDataRef;
import org.apache.wss4j.api.dom.WSConstants;

import org.apache.wss4j.api.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.dom.saml.SAMLCallback;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.dom.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.saml.message.WSSecSignatureSAML;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is some unit tests for signing using signature parts. Note that the "soapMsg" below
 * has a custom header added.
 */
public class SignaturePartsTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignaturePartsTest.class);
    private static final String SOAPMSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:foo=\"urn:foo.bar\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Header>" +
            "       <foo:foobar>baz</foo:foobar>" +
            "   </soapenv:Header>" +
            "   <soapenv:Body>" +
            "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test6/LogTestService8\"></ns1:testMethod>" +
            "   </soapenv:Body>" +
            "</soapenv:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();

    public SignaturePartsTest() throws Exception {
        WSSConfig.init();
    }

    /**
     * Test signing of a header through a STR Dereference Transform
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSOAPHeaderSTRTransform() throws Exception {
        // Construct issuer and user crypto instances
        Crypto issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SignaturePartsTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)issuerCrypto).setKeyStore(keyStore);

        Crypto userCrypto = CryptoFactory.getInstance("wss40.properties");

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);

        samlCallback.setIssuer("www.example.com");

        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("wss40", "security");

        WSEncryptionPart encP =
            new WSEncryptionPart("STRTransform", "", "Element");
        wsSign.getParts().add(encP);

        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(userCrypto, samlAssertion, null, null, null);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        // Construct trust crypto instance
        Crypto trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)trustCrypto).setTrustStore(trustStore);

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, trustCrypto);
        WSSecurityEngineResult stUnsignedActionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) stUnsignedActionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertNotNull(receivedSamlAssertion);
        assertTrue(receivedSamlAssertion.isSigned());

        WSSecurityEngineResult signActionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(signActionResult);
        assertFalse(signActionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) signActionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/wsse:Security/saml1:Assertion", xpath);
    }

}
