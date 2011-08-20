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
import org.swssf.securityEvent.SignedElementSecurityEvent;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignedElementAssertionState extends AssertionState {

    private List<QName> elements;

    public SignedElementAssertionState(AbstractSecurityAssertion assertion, boolean asserted, List<QName> elements) {
        super(assertion, asserted);
        this.elements = elements;
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
        for (int i = 0; i < elements.size(); i++) {
            QName qName = elements.get(i);
            if (qName.equals(signedElementSecurityEvent.getElement())) {
                if (signedElementSecurityEvent.isNotSigned()) {
                    //an element must be signed but isn't
                    setAsserted(false);
                    setErrorMessage("Element " + signedElementSecurityEvent.getElement() + " must be signed");
                    return false;
                } else {
                    setAsserted(true);
                }
            }
        }
        //if we return false here other signed elements will trigger a PolicyViolationException
        return true;
    }
}
