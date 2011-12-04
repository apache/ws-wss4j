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
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.UsernameTokenSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author $Author: giger $
 * @version $Revision: 1181995 $ $Date: 2011-10-11 20:03:00 +0200 (Tue, 11 Oct 2011) $
 */
public class UsernameTokenTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:UsernameToken xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" " +
                        "xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:HashPassword/>\n" +
                        "<sp:WssUsernameToken11/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:UsernameToken>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent(SecurityEvent.Event.UsernameToken);
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
        usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        policyEnforcer.registerSecurityEvent(usernameTokenSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNegative() throws Exception {
        String policyString =
                "<sp:UsernameToken xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" " +
                        "xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:HashPassword/>\n" +
                        "<sp:WssUsernameToken11/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:UsernameToken>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent(SecurityEvent.Event.UsernameToken);
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT);
        usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        try {
            policyEnforcer.registerSecurityEvent(usernameTokenSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }
}
