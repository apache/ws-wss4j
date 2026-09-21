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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.apache.neethi.Policy;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.policy.stax.OperationPolicy;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcerFactory;
import org.apache.wss4j.policy.stax.enforcer.PolicyInputProcessor;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.ext.SecurePart;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class VulnerabliltyVectorsTest extends AbstractTestBase {

    /**
     * Tests what happens when an soapAction from an other operation is provided.
     * Can the policy framework be bypassed?
     * @Ignoring as SOAP Action spoofing detection should be left to the SOAP stack
     */
    @Test
    @org.junit.jupiter.api.Disabled
    public void testSOAPActionSpoofing() throws Exception {
        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_WSU_TIMESTAMP, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);


        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("emptyPolicy", false, null, 0, false);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);
            fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            assertNotNull(throwable);
            assertTrue(throwable instanceof WSSecurityException);
            assertEquals(throwable.getMessage(),
                    "SOAPAction (emptyPolicyOperation) does not match with the current Operation: " +
                            "{http://schemas.xmlsoap.org/wsdl/}definitions");
            assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testSOAPActionMismatchFailsClosed() throws Exception {
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(
                this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("goodPolicy", false, null, 0, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://example.com/evil", "notGood"));

        WSSecurityException ex = assertThrows(WSSecurityException.class,
                () -> policyEnforcer.registerSecurityEvent(operationSecurityEvent));

        assertEquals("SOAPAction (goodPolicy) does not match with the current Operation: " +
                        "{http://example.com/evil}notGood",
                ex.getCause().getMessage());
        assertEquals(WSSecurityException.INVALID_SECURITY, ex.getFaultCode());
    }

    /**
     * An operation whose policy is registered without a namespace is matched on its local name
     * alone, which accepts a Body element in any namespace. That is only tenable while the
     * local name identifies one operation: once a second operation shares it, the local name no
     * longer says which of the two the SOAP stack will dispatch to, and the policy of the one
     * could be enforced for a message that invokes the other. Fail closed instead.
     */
    @Test
    public void testAmbiguousNoNamespaceOperationNameDoesNotMatchAnyNamespace() throws Exception {
        List<OperationPolicy> operationPolicies =
                Arrays.asList(operationPolicy(new QName(null, "getBalance"), null),
                        operationPolicy(new QName("http://www.example.net/secure", "getBalance"), null));

        PolicyEnforcer policyEnforcer =
                new PolicyEnforcer(operationPolicies, "", false, null, 0, null, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://www.example.net/other", "getBalance"));

        WSSecurityException ex = assertThrows(WSSecurityException.class,
                () -> policyEnforcer.registerSecurityEvent(operationSecurityEvent));

        assertEquals(WSSecurityException.INVALID_SECURITY, ex.getFaultCode());
    }

    /**
     * The same ambiguity on the SOAPAction path: the SOAPAction header selects the policy of the
     * operation registered without a namespace, while the Body element dispatches to the other
     * operation of that name. The cross-check added for SOAPAction spoofing must reject this.
     */
    @Test
    public void testAmbiguousNoNamespaceOperationNameDoesNotSatisfyTheSOAPActionCheck() throws Exception {
        List<OperationPolicy> operationPolicies =
                Arrays.asList(operationPolicy(new QName(null, "getBalance"), "urn:getBalanceUnsecured"),
                        operationPolicy(new QName("http://www.example.net/secure", "getBalance"), "urn:getBalance"));

        PolicyEnforcer policyEnforcer =
                new PolicyEnforcer(operationPolicies, "urn:getBalanceUnsecured", false, null, 0, null, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://www.example.net/secure", "getBalance"));

        WSSecurityException ex = assertThrows(WSSecurityException.class,
                () -> policyEnforcer.registerSecurityEvent(operationSecurityEvent));

        assertEquals("SOAPAction (urn:getBalanceUnsecured) does not match with the current Operation: "
                        + "{http://www.example.net/secure}getBalance",
                ex.getCause().getMessage());
        assertEquals(WSSecurityException.INVALID_SECURITY, ex.getFaultCode());
    }

    /**
     * An operation name that carries a namespace is matched exactly, so the policy of the
     * namespace-less operation of the same name is not selected for it.
     */
    @Test
    public void testNamespacedOperationNameSelectsItsOwnPolicy() throws Exception {
        List<OperationPolicy> operationPolicies =
                Arrays.asList(operationPolicy(new QName(null, "getBalance"), null),
                        operationPolicy(new QName("http://www.example.net/secure", "getBalance"), null));

        PolicyEnforcer policyEnforcer =
                new PolicyEnforcer(operationPolicies, "", false, null, 0, null, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://www.example.net/secure", "getBalance"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
    }

    /**
     * Where the local name is unambiguous the fallback is kept, so an integrator that registers
     * its operations without a namespace keeps working.
     */
    @Test
    public void testUnambiguousNoNamespaceOperationNameStillMatches() throws Exception {
        List<OperationPolicy> operationPolicies =
                Arrays.asList(operationPolicy(new QName(null, "getBalance"), null));

        PolicyEnforcer policyEnforcer =
                new PolicyEnforcer(operationPolicies, "", false, null, 0, null, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://www.example.net/other", "getBalance"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
    }

    /**
     * An rpc style operation is registered under the QName that will actually appear as the Body
     * child element - the operation name qualified with the namespace from soap:body - and so is
     * matched exactly rather than on its local name alone.
     */
    @Test
    public void testRpcOperationIsBoundToItsSOAPBodyNamespace() throws Exception {
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(
                this.getClass().getClassLoader().getResource("testdata/wsdl/rpcOperation.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("", false, null, 0, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://www.example.net/rpc", "getBalance"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
    }

    @Test
    public void testRpcOperationInAnotherNamespaceIsRejected() throws Exception {
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(
                this.getClass().getClassLoader().getResource("testdata/wsdl/rpcOperation.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("", false, null, 0, false);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("http://example.com/evil", "getBalance"));

        WSSecurityException ex = assertThrows(WSSecurityException.class,
                () -> policyEnforcer.registerSecurityEvent(operationSecurityEvent));

        assertEquals(WSSecurityException.INVALID_SECURITY, ex.getFaultCode());
    }

    private static OperationPolicy operationPolicy(QName operationName, String soapAction) {
        OperationPolicy operationPolicy = new OperationPolicy(operationName);
        operationPolicy.setPolicy(new Policy().normalize(true));
        operationPolicy.setOperationAction(soapAction);
        return operationPolicy;
    }

    @Test
    public void testSignedBodyRelocationToHeader() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Body");
        Element bodyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element soapEnvElement = (Element) bodyElement.getParentNode();
        soapEnvElement.removeChild(bodyElement);

        Element newBody = securedDocument.createElementNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_SOAP_BODY_LN);
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
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("goodPolicy", false, null, 0, false);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            doInboundSecurity(inSecurityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), policyEnforcer);
            fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            assertNotNull(throwable);
            assertTrue(throwable instanceof WSSecurityException);
            assertEquals(throwable.getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Body must be signed");
            assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}