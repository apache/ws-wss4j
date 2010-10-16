package ch.gigerstyle.xmlsec.policy.assertionStates;

import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SignedElementSecurityEvent;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * User: giger
 * Date: Oct 5, 2010
 * Time: 7:56:22 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignedElementAssertionState extends AssertionState {

    private List<QName> elements;

    public SignedElementAssertionState(AbstractSecurityAssertion assertion, boolean asserted, List<QName> elements) {
        super(assertion, asserted);
        this.elements = elements;
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        //here we add just one AssertionState for all Parts to get a fail-fast behavior
        //when we add multiple AssertionStates some of them return true, becauce they don't match
        //as a result the policy is temporary satisfied for the current event and can only be falsified at last
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
