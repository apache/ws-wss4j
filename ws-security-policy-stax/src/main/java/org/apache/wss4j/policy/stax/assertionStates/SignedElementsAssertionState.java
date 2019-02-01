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
import org.apache.wss4j.policy.model.SignedElements;
import org.apache.wss4j.policy.model.XPath;
import org.apache.xml.security.stax.securityEvent.AbstractSecuredElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyUtils;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.utils.WSSUtils;

import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * WSP1.3, 4.1.2 SignedElements Assertion
 */
public class SignedElementsAssertionState extends AssertionState implements Assertable {

    private final List<List<QName>> pathElements = new ArrayList<>();
    private PolicyAsserter policyAsserter;

    public SignedElementsAssertionState(AbstractSecurityAssertion assertion,
                                        PolicyAsserter policyAsserter,
                                        boolean asserted) {
        super(assertion, asserted);

        if (assertion instanceof SignedElements) {
            SignedElements signedElements = (SignedElements) assertion;
            for (int i = 0; i < signedElements.getXPaths().size(); i++) {
                XPath xPath = signedElements.getXPaths().get(i);
                List<QName> elements = PolicyUtils.getElementPath(xPath);
                pathElements.add(elements);
            }
        }

        this.policyAsserter = policyAsserter;
        if (this.policyAsserter == null) {
            this.policyAsserter = new DummyPolicyAsserter();
        }

        if (asserted) {
            policyAsserter.assertPolicy(getAssertion());
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                SecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART
        };
    }

    public void addElement(List<QName> pathElement) {
        this.pathElements.add(pathElement);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        AbstractSecuredElementSecurityEvent signedSecurityEvent = (AbstractSecuredElementSecurityEvent) securityEvent;

        Iterator<List<QName>> pathElementIterator = pathElements.iterator();
        while (pathElementIterator.hasNext()) {
            List<QName> pathElements = pathElementIterator.next();
            if (WSSUtils.pathMatches(pathElements, signedSecurityEvent.getElementPath())) {
                if (signedSecurityEvent.isSigned()) {
                    setAsserted(true);
                    policyAsserter.assertPolicy(getAssertion());
                    return true;
                } else {
                    //an element must be signed but isn't
                    setAsserted(false);
                    setErrorMessage("Element " + WSSUtils.pathAsString(signedSecurityEvent.getElementPath()) + " must be signed");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                    return false;
                }
            }
        }
        //if we return false here other signed elements will trigger a PolicyViolationException
        policyAsserter.assertPolicy(getAssertion());
        return true;
    }
}
