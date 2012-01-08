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
import org.swssf.wss.impl.securityToken.X509SecurityToken;
import org.swssf.wss.securityEvent.OperationSecurityEvent;
import org.swssf.wss.securityEvent.SignedPartSecurityEvent;
import org.swssf.wss.securityEvent.TimestampSecurityEvent;
import org.swssf.wss.securityEvent.X509TokenSecurityEvent;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class LayoutTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicyLaxTsFirst() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:Layout xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:LaxTsFirst/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:Layout>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(x509TokenSecurityEvent.getSecurityToken(), true);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyLaxTsFirstNegative() throws Exception {
        String policyString =
                "<sp:Layout xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:LaxTsFirst/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:Layout>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicyLaxTsLast() throws Exception {
        String policyString =
                "<sp:Layout xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:LaxTsLast/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:Layout>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyLaxTsLastNegative() throws Exception {
        String policyString =
                "<sp:Layout xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:LaxTsLast/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:Layout>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }
}
