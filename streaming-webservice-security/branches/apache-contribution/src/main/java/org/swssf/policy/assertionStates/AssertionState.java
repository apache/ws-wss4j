/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy.assertionStates;

import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.securityEvent.SecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AssertionState {

    private AbstractSecurityAssertion assertion;
    private boolean asserted;
    private StringBuilder errorMessage = new StringBuilder();

    public AssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        this.assertion = assertion;
        this.asserted = asserted;
    }

    public AbstractSecurityAssertion getAssertion() {
        return assertion;
    }

    public void setAsserted(boolean asserted) {
        this.asserted = asserted;
    }

    public boolean isAsserted() {
        return asserted;
    }

    public boolean assertEvent(SecurityEvent securityEvent) {
        if (securityEvent != null) {
            this.asserted = true;
        }
        return this.asserted;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage.append("\n").append(errorMessage);
    }

    public String getErrorMessage() {
        if (errorMessage.length() == 0) {
            return "Assertion " + assertion.getName() + " not satisfied";
        } else {
            return errorMessage.toString();
        }
    }
}
