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
import org.swssf.securityEvent.RequiredPartSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class RequiredPartAssertionState extends AssertionState {

    private QName element;

    public RequiredPartAssertionState(AbstractSecurityAssertion assertion, boolean asserted, QName element) {
        super(assertion, asserted);
        this.element = element;
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        RequiredPartSecurityEvent requiredPartSecurityEvent = (RequiredPartSecurityEvent) securityEvent;
        if (element.equals(requiredPartSecurityEvent.getElement())
                || (element.getLocalPart().equals("*") && element.getNamespaceURI().equals(requiredPartSecurityEvent.getElement().getNamespaceURI()))) {
            setAsserted(true);
        }
        return true;
    }
}
