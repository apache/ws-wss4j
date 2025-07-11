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
package org.apache.wss4j.policy.stax.assertionStates;

import org.apache.wss4j.policy.AssertionState;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.Layout;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.api.stax.securityEvent.WSSecurityEventConstants;

import java.util.ArrayList;
import java.util.List;

public class LayoutAssertionState extends AssertionState implements Assertable {

    private List<SecurityEventConstants.Event> occuredEvents = new ArrayList<>();

    public LayoutAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.USERNAME_TOKEN,
                WSSecurityEventConstants.ISSUED_TOKEN,
                SecurityEventConstants.X509Token,
                WSSecurityEventConstants.KERBEROS_TOKEN,
                WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                WSSecurityEventConstants.SAML_TOKEN,
                WSSecurityEventConstants.REL_TOKEN,
                WSSecurityEventConstants.HTTPS_TOKEN,
                SecurityEventConstants.KeyValueToken,
                WSSecurityEventConstants.TIMESTAMP,
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        Layout layout = (Layout) getAssertion();
        switch (layout.getLayoutType()) {
            case Strict:
                //todo
                break;
            case Lax:
                //todo?
                break;
            case LaxTsFirst:
                if (occuredEvents.isEmpty()
                    && !WSSecurityEventConstants.TIMESTAMP.equals(securityEvent.getSecurityEventType())) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + layout.getLayoutType() + " but "
                        + securityEvent.getSecurityEventType() + " occured first");
                }
                break;
            case LaxTsLast:
                if (occuredEvents.contains(WSSecurityEventConstants.TIMESTAMP)) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + layout.getLayoutType() + " but "
                        + securityEvent.getSecurityEventType() + " occured last");
                }
                break;
        }
        occuredEvents.add(securityEvent.getSecurityEventType());
        return isAsserted();
    }
}
