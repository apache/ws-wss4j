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
import org.swssf.policy.secpolicy.model.Binding;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.TimestampSecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class IncludeTimeStampAssertionState extends AssertionState {

    public IncludeTimeStampAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    public boolean assertEvent(SecurityEvent securityEvent) {
        TimestampSecurityEvent timestampSecurityEvent = (TimestampSecurityEvent) securityEvent;
        boolean isIncludeTimestamp = ((Binding) getAssertion()).isIncludeTimestamp();

        if (isIncludeTimestamp) {
            setAsserted(true);
        } else {
            setAsserted(false);
            setErrorMessage("Timestamp must not be present");
        }
        return isAsserted();
    }
}
