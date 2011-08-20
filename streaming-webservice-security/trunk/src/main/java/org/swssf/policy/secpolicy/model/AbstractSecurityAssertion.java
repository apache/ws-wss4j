/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.swssf.policy.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public abstract class AbstractSecurityAssertion implements Assertion {

    private boolean isOptional;

    private boolean normalized = false;

    protected SPConstants spConstants;

    public boolean isOptional() {
        return isOptional;
    }

    public void setOptional(boolean isOptional) {
        this.isOptional = isOptional;
    }

    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }

    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }

    public void setNormalized(boolean normalized) {
        this.normalized = normalized;
    }

    public boolean isNormalized() {
        return this.normalized;
    }

    public PolicyComponent normalize() {

        /*
        * TODO: Handling the isOptional:TRUE case
        */
        return this;
    }

    public void setVersion(SPConstants spConstants) {
        this.spConstants = spConstants;
    }

    public SPConstants.Version getVersion() {
        return spConstants.getVersion();
    }

    public abstract SecurityEvent.Event[] getResponsibleAssertionEvents();

    public abstract void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy);

    public boolean isAsserted(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) {

        boolean asserted = true;

        SecurityEvent.Event[] secEvents = getResponsibleAssertionEvents();
        for (int i = 0; i < secEvents.length; i++) {
            SecurityEvent.Event securityEvent = secEvents[i];

            Map<Assertion, List<AssertionState>> assertionStates = assertionStateMap.get(securityEvent);
            for (Iterator<Map.Entry<Assertion, List<AssertionState>>> assertionStateIterator = assertionStates.entrySet().iterator(); assertionStateIterator.hasNext(); ) {
                Map.Entry<Assertion, List<AssertionState>> entry = assertionStateIterator.next();
                if (entry.getKey() == this) {
                    List<AssertionState> assertionState = entry.getValue();
                    for (int j = 0; j < assertionState.size(); j++) {
                        AssertionState state = assertionState.get(j);
                        asserted &= state.isAsserted();
                    }
                }
            }
        }
        return asserted;
    }

    protected void addAssertionState(Map<Assertion, List<AssertionState>> assertionStates, Assertion keyAssertion, AssertionState assertionState) {
        List<AssertionState> assertionStateList = assertionStates.get(keyAssertion);
        if (assertionStateList == null) {
            assertionStateList = new ArrayList<AssertionState>();
        }
        assertionStateList.add(assertionState);
        assertionStates.put(keyAssertion, assertionStateList);
    }
}
