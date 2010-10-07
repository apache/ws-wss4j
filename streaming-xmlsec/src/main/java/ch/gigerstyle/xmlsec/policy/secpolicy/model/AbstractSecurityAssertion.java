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
package ch.gigerstyle.xmlsec.policy.secpolicy.model;

import ch.gigerstyle.xmlsec.policy.assertionStates.AssertionState;
import ch.gigerstyle.xmlsec.policy.secpolicy.SPConstants;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

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
        return true;
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

    public abstract void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap);

    public boolean isAsserted(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {

        boolean asserted = true;

        SecurityEvent.Event[] secEvents = getResponsibleAssertionEvents();
        for (int i = 0; i < secEvents.length; i++) {
            SecurityEvent.Event securityEvent = secEvents[i];

            Collection<AssertionState> assertionStates = assertionStateMap.get(securityEvent);
            for (Iterator<AssertionState> assertionStateIterator = assertionStates.iterator(); assertionStateIterator.hasNext();) {
                AssertionState assertionState = assertionStateIterator.next();
                if (assertionState.getAssertion() == this) {
                    asserted &= assertionState.isAsserted();
                }
            }
        }
        return asserted;
    }
}
