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
package org.apache.wss4j.stax.test.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;

import javax.xml.stream.XMLStreamReader;
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
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SamlTokenDerivedTest extends AbstractTestBase {

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion
     * using a derived key.
     */
    @Test
    public void testSAML1AuthnAssertionDerivedInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            //
            // Create a SAML Assertion + STR, and add both to the security header
            //
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            SAMLCallback samlCallback = new SAMLCallback();
            SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
            SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            SecurityTokenReference secRefSaml =
                    createSamlSTR(doc, samlAssertion, WSSConfig.getNewInstance());
            Element samlTokenElement = samlAssertion.toDOM(doc);
            Element secRefElement = secRefSaml.getElement();
            secHeader.getSecurityHeader().appendChild(samlTokenElement);
            secHeader.getSecurityHeader().appendChild(secRefElement);

            //
            // Create a Derived Key object for signature
            //
            WSSecDKSign sigBuilder = createDKSign(doc, secRefSaml);
            Document securedDocument = sigBuilder.build(doc, secHeader);

            //todo remove the following lines when the header ordering no longer does matter...
            /*Node firstChild = secHeader.getSecurityHeader().getFirstChild();
            secHeader.getSecurityHeader().insertBefore(secRefElement, firstChild);
            secHeader.getSecurityHeader().insertBefore(samlTokenElement, secRefElement);*/

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] securityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.SAML_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SignedElement,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            TestSecurityEventListener testSecurityEventListener = new TestSecurityEventListener(securityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, testSecurityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            testSecurityEventListener.compare();
        }
    }

    /**
     * Create a SecurityTokenReference to a SAML Assertion
     */
    private SecurityTokenReference createSamlSTR(
            Document doc,
            SamlAssertionWrapper samlAssertion,
            WSSConfig wssConfig
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
            Document doc,
            SecurityTokenReference secRefSaml
    ) throws WSSecurityException {
        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("transmitter");
        Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierThumb(certs[0]);

        WSSecDKSign sigBuilder = new WSSecDKSign();
        java.security.Key key =
                crypto.getPrivateKey("transmitter", "default");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);

        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart encP =
                new WSEncryptionPart(
                        WSConstants.ELEM_BODY,
                        soapNamespace,
                        "Content"
                );
        sigBuilder.getParts().add(encP);

        encP = new WSEncryptionPart("STRTransform", "", "Element");
        encP.setId(secRefSaml.getID());
        encP.setElement(secRefSaml.getElement());
        sigBuilder.getParts().add(encP);

        return sigBuilder;
    }
}
