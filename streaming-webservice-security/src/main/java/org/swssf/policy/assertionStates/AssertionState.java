/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy.assertionStates;

import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.securityEvent.SecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class AssertionState {

    private AbstractSecurityAssertion assertion;
    private boolean asserted;
    private String errorMessage;

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
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        if (errorMessage == null) {
            return "Assertion " + assertion.getName() + " not satisfied";
        } else {
            return errorMessage;
        }
    }
}
