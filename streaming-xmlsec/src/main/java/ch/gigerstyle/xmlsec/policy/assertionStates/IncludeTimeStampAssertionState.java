package ch.gigerstyle.xmlsec.policy.assertionStates;

import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.Binding;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.TimestampSecurityEvent;

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
