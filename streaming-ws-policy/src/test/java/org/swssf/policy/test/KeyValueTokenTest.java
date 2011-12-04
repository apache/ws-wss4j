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
import org.swssf.wss.securityEvent.KeyValueTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.testng.annotations.Test;

/**
 * @author $Author: giger $
 * @version $Revision: 1181995 $ $Date: 2011-10-11 20:03:00 +0200 (Tue, 11 Oct 2011) $
 */
public class KeyValueTokenTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:KeyValueToken xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" " +
                        "xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:RsaKeyValue/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:KeyValueToken>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        KeyValueTokenSecurityEvent keyValueTokenSecurityEvent = new KeyValueTokenSecurityEvent(SecurityEvent.Event.KeyValueToken);
        policyEnforcer.registerSecurityEvent(keyValueTokenSecurityEvent);
        policyEnforcer.doFinal();
    }

    //todo more tests
}
