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
package org.apache.wss4j.policy.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.policy.stax.enforcer.PolicyInputProcessor;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.saml.SAML1CallbackHandler;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class STRTransformSignedPartsTest extends AbstractPolicyTestBase {

    private static final String WSDL_NS = "http://schemas.xmlsoap.org/wsdl/";

    /**
     * The message signs the SOAP Body and, via an STR-Transform, a SAML Assertion. The (unsigned)
     * wsdl:definitions SOAP header of the test message follows the security header, so the policy
     * enforcer must still flag it as not signed.
     */
    @Test
    public void testSTRTransformDoesNotDisableSignedPartsEnforcement() throws Exception {

        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n"
                        + "<sp:Body/>\n"
                        + "<sp:Header Name=\"definitions\" Namespace=\"" + WSDL_NS + "\"/>\n"
                        + "</sp:SignedParts>";

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        SecurityTokenReference secRefSaml = createSamlSTR(doc, samlAssertion, WSSConfig.getNewInstance());
        secHeader.getSecurityHeaderElement().appendChild(samlAssertion.toDOM(doc));
        secHeader.getSecurityHeaderElement().appendChild(secRefSaml.getElement());

        WSSecDKSign sigBuilder = createDKSign(doc, secRefSaml, secHeader);
        Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
        java.security.Key key = crypto.getPrivateKey("transmitter", "default");
        Document securedDocument = sigBuilder.build(key.getEncoded());

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(
                this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(
                this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);
            fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            assertNotNull(throwable);
            assertTrue(throwable instanceof WSSecurityException);
            assertEquals("Element /{" + WSConstants.URI_SOAP11_ENV + "}Envelope"
                            + "/{" + WSConstants.URI_SOAP11_ENV + "}Header"
                            + "/{" + WSDL_NS + "}definitions must be signed",
                    throwable.getMessage());
            assertEquals(WSSecurityException.INVALID_SECURITY, ((WSSecurityException) throwable).getFaultCode());
        }
    }

    /**
     * Create a SecurityTokenReference to a SAML Assertion
     */
    private SecurityTokenReference createSamlSTR(
            Document doc, SamlAssertionWrapper samlAssertion, WSSConfig wssConfig
    ) {
        SecurityTokenReference secRefSaml = new SecurityTokenReference(doc);
        String secRefID = wssConfig.getIdAllocator().createSecureId("STRSAMLId-", secRefSaml);
        secRefSaml.setID(secRefID);

        org.apache.wss4j.common.token.Reference ref =
                new org.apache.wss4j.common.token.Reference(doc);
        ref.setURI("#" + samlAssertion.getId());
        ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        secRefSaml.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
        secRefSaml.setReference(ref);

        return secRefSaml;
    }

    /**
     * Create a WSSecDKSign object, that signs the SOAP Body as well as the SAML Assertion
     * via a STR Transform.
     */
    private WSSecDKSign createDKSign(
            Document doc, SecurityTokenReference secRefSaml, WSSecHeader secHeader
    ) throws WSSecurityException {
        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("transmitter");
        Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierThumb(certs[0]);

        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        sigBuilder.setStrElem(secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);

        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart encP =
                new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
        sigBuilder.getParts().add(encP);

        encP = new WSEncryptionPart("STRTransform", "", "Element");
        encP.setId(secRefSaml.getID());
        Element secRefElement = secRefSaml.getElement();
        encP.setElement(secRefElement);
        sigBuilder.getParts().add(encP);

        return sigBuilder;
    }
}
