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
package org.swssf.policy.test;

import org.swssf.policy.PolicyEnforcer;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.X509SecurityToken;
import org.swssf.wss.securityEvent.*;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class X509TokenTest extends AbstractPolicyTestBase {

    public X509SecurityToken getX509Token(WSSConstants.TokenType tokenType) throws Exception {

        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());

        return new X509SecurityToken(tokenType, null, null, null, "", WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return "transmitter";
            }

            @Override
            public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                try {
                    return keyStore.getKey("transmitter", "default".toCharArray());
                } catch (Exception e) {
                    throw new XMLSecurityException(e.getMessage(), e);
                }
            }

            @Override
            public PublicKey getPublicKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                try {
                    return keyStore.getCertificate("transmitter").getPublicKey();
                } catch (Exception e) {
                    throw new XMLSecurityException(e.getMessage(), e);
                }
            }

            @Override
            public X509Certificate[] getX509Certificates() throws XMLSecurityException {
                Certificate[] certificates;
                try {
                    certificates = keyStore.getCertificateChain("transmitter");
                } catch (Exception e) {
                    throw new XMLSecurityException(e.getMessage(), e);
                }

                X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
                for (int i = 0; i < certificates.length; i++) {
                    Certificate certificate = certificates[i];
                    x509Certificates[i] = (X509Certificate) certificate;
                }
                return x509Certificates;
            }
        };
    }

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:RecipientToken>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
        initiatorX509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V3Token));
        initiatorX509TokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        recipientX509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V3Token));
        recipientX509TokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(recipientX509TokenSecurityEvent.getSecurityToken(), true);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(recipientX509TokenSecurityEvent.getSecurityToken(), true, true);
        contentEncryptedElementSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNegative() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:RecipientToken>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
        initiatorX509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V1Token));
        initiatorX509TokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        recipientX509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V3Token));
        recipientX509TokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(recipientX509TokenSecurityEvent.getSecurityToken(), true);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(recipientX509TokenSecurityEvent.getSecurityToken(), true, true);
        contentEncryptedElementSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "An error was discovered processing the <wsse:Security> header; nested exception is: \n" +
                    "\torg.swssf.policy.PolicyViolationException: No policy alternative could be satisfied");
        }
    }

    @Test
    public void testSupportingTokenPolicy() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V3Token));
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testSupportingTokenPolicyNegative() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(getX509Token(WSSConstants.X509V1Token));
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "An error was discovered processing the <wsse:Security> header; nested exception is: \n" +
                    "\torg.swssf.policy.PolicyViolationException: No policy alternative could be satisfied");
        }
    }
}
