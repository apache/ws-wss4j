package ch.gigerstyle.xmlsec.policy.assertionStates;

import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;

/**
 * User: giger
 * Date: Oct 5, 2010
 * Time: 6:38:07 PM
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
