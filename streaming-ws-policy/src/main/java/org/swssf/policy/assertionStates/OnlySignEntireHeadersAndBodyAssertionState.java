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
import org.apache.ws.secpolicy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.ws.secpolicy.model.AsymmetricBinding;
import org.swssf.policy.Assertable;
import org.swssf.policy.PolicyConstants;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignedPartSecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 1181995 $ $Date: 2011-10-11 20:03:00 +0200 (Tue, 11 Oct 2011) $
 */
public class OnlySignEntireHeadersAndBodyAssertionState extends AssertionState implements Assertable {

    public OnlySignEntireHeadersAndBodyAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SignedPart
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        SignedPartSecurityEvent signedPartSecurityEvent = (SignedPartSecurityEvent) securityEvent;
        AbstractSymmetricAsymmetricBinding asymmetricBinding = (AbstractSymmetricAsymmetricBinding) getAssertion();
        if (!asymmetricBinding.isOnlySignEntireHeadersAndBody()) {
            setAsserted(true);
            return true;
        }
        if (asymmetricBinding.isOnlySignEntireHeadersAndBody()
                && (signedPartSecurityEvent.getElement().equals(PolicyConstants.TAG_soap11_Body)
                || signedPartSecurityEvent.getElement().equals(PolicyConstants.TAG_soap12_Body))) {
            if (signedPartSecurityEvent.isSigned()) {
                setAsserted(true);
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + signedPartSecurityEvent.getElement() + " must be signed");
                return false;
            }
        }
        //body processed above. so this must be a header element
        if (asymmetricBinding.isOnlySignEntireHeadersAndBody()) {
            if (signedPartSecurityEvent.isSigned()) {
                setAsserted(true);
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + signedPartSecurityEvent.getElement() + " must be signed");
                return false;
            }
        }
        return true;
    }
}
