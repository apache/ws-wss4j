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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.policy.stax.PolicyEnforcerFactory;
import org.apache.wss4j.policy.stax.PolicyInputProcessor;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.ext.SecurePart;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class VulnerabliltyVectorsTest extends AbstractTestBase {

    /**
     * Tests what happens when an soapAction from an other operation is provided.
     * Can the policy framework be bypassed?
     * @Ignoring as SOAP Action spoofing detection should be left to the SOAP stack
     */
    @Test
    @org.junit.Ignore
    public void testSOAPActionSpoofing() throws Exception {
        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);


        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("emptyPolicy", false, null, 0);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            Assert.assertEquals(throwable.getMessage(),
                    "SOAPAction (emptyPolicyOperation) does not match with the current Operation: " +
                            "{http://schemas.xmlsoap.org/wsdl/}definitions");
            Assert.assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testSignedBodyRelocationToHeader() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Body");
        Element bodyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element soapEnvElement = (Element) bodyElement.getParentNode();
        soapEnvElement.removeChild(bodyElement);

        Element newBody = securedDocument.createElementNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
        Element operationElement = securedDocument.createElementNS("http://schemas.xmlsoap.org/wsdl/", "definitions");
        newBody.appendChild(operationElement);
        soapEnvElement.appendChild(newBody);

        xPathExpression = getXPath("/soap:Envelope/soap:Header");
        Element headerElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        headerElement.appendChild(bodyElement);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("goodPolicy", false, null, 0);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            doInboundSecurity(inSecurityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), policyEnforcer);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            Assert.assertEquals(throwable.getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Body must be signed");
            Assert.assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}
