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
import java.io.InputStream;
import java.util.Collections;

import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.policy.stax.enforcer.PolicyInputProcessor;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.saml.SAMLCallbackHandlerImpl;
import org.apache.xml.security.stax.ext.SecurePart;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SamlSTRTransformSignedElementsTest extends AbstractPolicyTestBase {

    @Test
    public void testSaml11STRTransformSatisfiesSignedElements() throws Exception {
        SAMLCallbackHandlerImpl samlCallback = new SAMLCallbackHandlerImpl();
        samlCallback.setSamlVersion(Version.SAML_11);
        samlCallback.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
        samlCallback.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        samlCallback.setIssuer("www.example.com");
        samlCallback.setSignAssertion(false);

        WSSSecurityProperties outbound = new WSSSecurityProperties();
        outbound.setActions(Collections.singletonList(WSSConstants.SAML_TOKEN_SIGNED));
        outbound.setSamlCallbackHandler(samlCallback);
        outbound.setCallbackHandler(new CallbackHandlerImpl());
        outbound.loadSignatureKeyStore(getClass().getClassLoader().getResource("transmitter.jks"),
                "default".toCharArray());
        outbound.setSignatureUser("transmitter");
        outbound.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        outbound.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));

        byte[] message;
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml")) {
            message = doOutboundSecurity(outbound, input).toByteArray();
        }

        // The same message must first pass signature and sender-vouches validation without a policy.
        Document verified = doInboundSecurity(inboundProperties(), new ByteArrayInputStream(message));
        NodeList assertions = verified.getElementsByTagNameNS(WSSConstants.NS_SAML, "Assertion");
        assertEquals(1, assertions.getLength());
        Element assertion = (Element) assertions.item(0);
        assertEquals(0, assertion.getElementsByTagNameNS(WSSConstants.NS_DSIG, "Signature").getLength());
        NodeList transforms = verified.getElementsByTagNameNS(WSSConstants.NS_DSIG, "Transform");
        boolean strTransformFound = false;
        for (int i = 0; i < transforms.getLength(); i++) {
            Element transform = (Element) transforms.item(i);
            strTransformFound |= WSSConstants.SOAPMESSAGE_NS10_STR_TRANSFORM.equals(transform.getAttribute("Algorithm"));
        }
        assertTrue(strTransformFound, "The SOAP signature must cover the assertion through an STR Transform");

        String policy =
                "<sp:SignedElements xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">"
                        + "<sp:XPath xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
                        + "xmlns:saml1=\"urn:oasis:names:tc:SAML:1.0:assertion\">"
                        + "/soap:Envelope/soap:Header/wsse:Security/saml1:Assertion</sp:XPath>"
                        + "</sp:SignedElements>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policy);
        WSSSecurityProperties inbound = inboundProperties();
        inbound.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inbound));

        // STR Transform signs the assertion, so enabling this policy must also accept the message.
        Document processed = doInboundSecurity(inbound, new ByteArrayInputStream(message), policyEnforcer);
        assertEquals(1, processed.getElementsByTagNameNS(WSSConstants.NS_SAML, "Assertion").getLength());
    }

    private WSSSecurityProperties inboundProperties() throws Exception {
        WSSSecurityProperties properties = new WSSSecurityProperties();
        properties.loadSignatureVerificationKeystore(getClass().getClassLoader().getResource("receiver.jks"),
                "default".toCharArray());
        return properties;
    }
}
