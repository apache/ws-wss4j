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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.AssertionState;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.Layout;
import org.swssf.policy.Assertable;
import org.swssf.wss.securityEvent.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class LayoutAssertionState extends AssertionState implements Assertable {

    private List<SecurityEvent.Event> occuredEvents = new ArrayList<SecurityEvent.Event>();

    public LayoutAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.UsernameToken,
                SecurityEvent.Event.IssuedToken,
                SecurityEvent.Event.X509Token,
                SecurityEvent.Event.KerberosToken,
                SecurityEvent.Event.SpnegoContextToken,
                SecurityEvent.Event.SecurityContextToken,
                SecurityEvent.Event.SecureConversationToken,
                SecurityEvent.Event.SamlToken,
                SecurityEvent.Event.RelToken,
                SecurityEvent.Event.HttpsToken,
                SecurityEvent.Event.KeyValueToken,
                SecurityEvent.Event.Timestamp,
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
                if (occuredEvents.isEmpty() && securityEvent.getSecurityEventType() != SecurityEvent.Event.Timestamp) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + layout.getLayoutType() + " but " + securityEvent.getSecurityEventType() + " occured first");
                }
                break;
            case LaxTsLast:
                if (occuredEvents.contains(SecurityEvent.Event.Timestamp)) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + layout.getLayoutType() + " but " + securityEvent.getSecurityEventType() + " occured last");
                }
                break;
        }
        occuredEvents.add(securityEvent.getSecurityEventType());
        return isAsserted();
    }
}
