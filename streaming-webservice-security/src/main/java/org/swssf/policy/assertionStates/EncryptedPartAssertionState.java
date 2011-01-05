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
import org.swssf.securityEvent.EncryptedPartSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class EncryptedPartAssertionState extends AssertionState {

    private List<QName> elements;

    public EncryptedPartAssertionState(AbstractSecurityAssertion assertion, boolean asserted, List<QName> elements) {
        super(assertion, asserted);
        this.elements = elements;
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
        for (int i = 0; i < elements.size(); i++) {
            QName qName = elements.get(i);
            if (qName.equals(encryptedPartSecurityEvent.getElement())
                    || (qName.getLocalPart().equals("*") && qName.getNamespaceURI().equals(encryptedPartSecurityEvent.getElement().getNamespaceURI()))) {
                if (encryptedPartSecurityEvent.isNotEncrypted()) {
                    //an element must be encrypted but isn't
                    setAsserted(false);
                    setErrorMessage("Element " + encryptedPartSecurityEvent.getElement() + " must be encrypted");
                    return false;
                } else {
                    setAsserted(true);
                }
            }
        }
        //if we return false here other encrypted elements will trigger a PolicyViolationException
        return true;
    }
}
