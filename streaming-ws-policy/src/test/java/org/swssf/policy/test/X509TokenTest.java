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
import org.swssf.policy.PolicyViolationException;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.DelegatingSecurityToken;
import org.swssf.wss.impl.securityToken.X509SecurityToken;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.X509TokenSecurityEvent;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author $Author: giger $
 * @version $Revision: 1181995 $ $Date: 2011-10-11 20:03:00 +0200 (Tue, 11 Oct 2011) $
 */
public class X509TokenTest extends AbstractPolicyTestBase {

    public X509SecurityToken getX509Token(WSSConstants.TokenType tokenType) throws Exception {

        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());

        return new X509SecurityToken(tokenType, null, null, null, "", null) {
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
            public PublicKey getPublicKey(XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
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
                "<sp:X509Token xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" " +
                        "xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:RequireThumbprintReference/>\n" +
                        "<sp:WssX509V3Token11/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:X509Token>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent(SecurityEvent.Event.X509Token);
        x509TokenSecurityEvent.setSecurityToken(
                new DelegatingSecurityToken(WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER,
                        getX509Token(WSSConstants.X509V3Token)));
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNegative() throws Exception {
        String policyString =
                "<sp:X509Token xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" " +
                        "xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:RequireThumbprintReference/>\n" +
                        "<sp:WssX509V3Token11/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:X509Token>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent(SecurityEvent.Event.X509Token);
        x509TokenSecurityEvent.setSecurityToken(
                new DelegatingSecurityToken(WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER,
                        getX509Token(WSSConstants.X509V1Token)));
        try {
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }
}
