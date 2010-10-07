package ch.gigerstyle.xmlsec.policy.assertionStates;

import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SignedElementSecurityEvent;

import javax.xml.namespace.QName;

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

    private QName element;

    public SignedElementAssertionState(AbstractSecurityAssertion assertion, boolean asserted, QName element) {
        super(assertion, asserted);
        this.element = element;
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
        if (element.equals(signedElementSecurityEvent.getElement())) {
            setAsserted(true);
        }
        //if we return false here other signed elements will trigger a PolicyViolationException
        return true;
    }
}
