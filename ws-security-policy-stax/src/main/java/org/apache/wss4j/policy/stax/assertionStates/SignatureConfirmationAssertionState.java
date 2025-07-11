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

import javax.xml.namespace.QName;

import org.apache.wss4j.policy.AssertionState;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.Wss11;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.api.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;

public class SignatureConfirmationAssertionState extends AssertionState implements Assertable {

    private PolicyAsserter policyAsserter;

    public SignatureConfirmationAssertionState(AbstractSecurityAssertion assertion,
                                               PolicyAsserter policyAsserter,
                                               boolean asserted) {
        super(assertion, asserted);

        this.policyAsserter = policyAsserter;
        if (this.policyAsserter == null) {
            this.policyAsserter = new DummyPolicyAsserter();
        }

        if (asserted) {
            String namespace = getAssertion().getName().getNamespaceURI();
            policyAsserter.assertPolicy(new QName(namespace, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION));
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SIGNATURE_CONFIRMATION
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        Wss11 wss11 = (Wss11)getAssertion();

        String namespace = getAssertion().getName().getNamespaceURI();
        if (wss11.isRequireSignatureConfirmation()) {
            policyAsserter.assertPolicy(new QName(namespace, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION));
            setAsserted(true);
        } else {
            setAsserted(false);
            setErrorMessage("Signature confirmation elements must not be used");
            policyAsserter.unassertPolicy(new QName(namespace, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION),
                                          getErrorMessage());
        }
        return isAsserted();
    }
}
