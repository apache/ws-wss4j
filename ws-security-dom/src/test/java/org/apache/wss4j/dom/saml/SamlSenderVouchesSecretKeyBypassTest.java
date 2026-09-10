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

package org.apache.wss4j.dom.saml;

import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.STRParserParameters;
import org.apache.wss4j.dom.str.STRParserResult;
import org.apache.wss4j.dom.str.SignatureSTRParser;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Regression test for a sender-vouches trust bypass: an unsigned SAML assertion carries a raw,
 * attacker-chosen secret key in its Subject KeyInfo (SubjectConfirmationData/ds:KeyInfo/wst:BinarySecret).
 * That confirmation method is not holder-of-key, so the secret has no defined proof-of-possession
 * semantics and no trust anchor is ever consulted for it - SignatureTrustValidator only validates
 * certs/public keys, so a raw secret credential used to "verify" a signature is a self-referential
 * no-op that any attacker can satisfy. SignatureSTRParser must reject such a credential instead of
 * silently handing back the attacker's own key.
 */
public class SamlSenderVouchesSecretKeyBypassTest {

    private static final String WST_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";

    public SamlSenderVouchesSecretKeyBypassTest() throws Exception {
        WSSConfig.init();
    }

    @Test
    public void testUnsignedSenderVouchesSubjectSecretKeyIsRejected() throws Exception {
        // An unsigned, sender-vouches SAML assertion (the default for SAML1CallbackHandler) whose
        // Subject KeyInfo embeds a raw secret of the attacker's own choosing.
        byte[] attackerSecret = "attacker-controlled-shared-secret".getBytes("UTF-8");

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("attacker.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        samlCallback.getSubject().setKeyInfo(createBinarySecretKeyInfo(attackerSecret));

        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        samlAssertion.toDOM(doc);
        samlAssertion.parseSubject(new WSSSAMLKeyInfoProcessor(new RequestData()), null, null);

        assertThrows(WSSecurityException.class, () -> parseSubjectKeyIdentifier(doc, samlAssertion));
    }

    // Directly exercises SignatureSTRParser, i.e. what a ds:Signature's KeyInfo/SecurityTokenReference
    // resolves to when it points at the SAML assertion above - this is the exact sink that a forged
    // "self-vouching" HMAC signature over the SOAP Body would rely on.
    private STRParserResult parseSubjectKeyIdentifier(
        Document doc, SamlAssertionWrapper samlAssertion
    ) throws WSSecurityException {
        WSDocInfo wsDocInfo = new WSDocInfo(doc);
        WSSecurityEngineResult samlResult =
            new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, samlAssertion);
        samlResult.put(WSSecurityEngineResult.TAG_ID, samlAssertion.getId());
        wsDocInfo.addResult(samlResult);

        RequestData requestData = new RequestData();
        requestData.setWsDocInfo(wsDocInfo);

        SecurityTokenReference secRef = new SecurityTokenReference(doc);
        secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
        secRef.setKeyIdentifier(WSConstants.WSS_SAML_KI_VALUE_TYPE, samlAssertion.getId());

        STRParserParameters parameters = new STRParserParameters();
        parameters.setData(requestData);
        parameters.setStrElement(secRef.getElement());

        STRParser strParser = new SignatureSTRParser();
        return strParser.parseSecurityTokenReference(parameters);
    }

    private KeyInfoBean createBinarySecretKeyInfo(byte[] secret) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder docBuilder = dbf.newDocumentBuilder();
        Document keyInfoDoc = docBuilder.newDocument();

        Element keyInfoElement = keyInfoDoc.createElementNS(WSConstants.SIG_NS, "ds:KeyInfo");
        keyInfoElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", WSConstants.SIG_NS);
        Element binarySecretElement = keyInfoDoc.createElementNS(WST_NS, "wst:BinarySecret");
        binarySecretElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:wst", WST_NS);
        binarySecretElement.setTextContent(Base64.getEncoder().encodeToString(secret));
        keyInfoElement.appendChild(binarySecretElement);
        keyInfoDoc.appendChild(keyInfoElement);

        KeyInfoBean keyInfo = new KeyInfoBean();
        keyInfo.setElement(keyInfoElement);
        return keyInfo;
    }
}
