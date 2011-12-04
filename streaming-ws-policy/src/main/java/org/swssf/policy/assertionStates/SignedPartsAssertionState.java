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
import org.apache.ws.secpolicy.model.Header;
import org.apache.ws.secpolicy.model.SignedParts;
import org.swssf.policy.Assertable;
import org.swssf.policy.PolicyConstants;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignedPartSecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignedPartsAssertionState extends AssertionState implements Assertable {

    public SignedPartsAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
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

        //todo attachments

        SignedPartSecurityEvent signedPartSecurityEvent = (SignedPartSecurityEvent) securityEvent;
        SignedParts signedParts = (SignedParts) getAssertion();

        if (signedParts.isBody() && (signedPartSecurityEvent.getElement().equals(PolicyConstants.TAG_soap11_Body)
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
        if (signedParts.isSignAllHeaders()) {
            if (signedPartSecurityEvent.isSigned()) {
                setAsserted(true);
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + signedPartSecurityEvent.getElement() + " must be signed");
                return false;
            }
        } else {
            for (int i = 0; i < signedParts.getHeaders().size(); i++) {
                Header header = signedParts.getHeaders().get(i);
                if (header.getNamespace().equals(signedPartSecurityEvent.getElement().getNamespaceURI())
                        && (header.getName() == null //== wildcard
                        || header.getName().equals(signedPartSecurityEvent.getElement().getLocalPart()))) {
                    if (signedPartSecurityEvent.isSigned()) {
                        setAsserted(true);
                        return true;
                    } else {
                        setAsserted(false);
                        setErrorMessage("Element " + signedPartSecurityEvent.getElement() + " must be signed");
                        return false;
                    }
                }
            }
        }

        //if we return false here other signed elements will trigger a PolicyViolationException
        return true;
    }
}
