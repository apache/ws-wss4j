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

import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.policy.secpolicy.model.SymmetricAsymmetricBindingBase;
import org.swssf.securityEvent.EncryptionTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureTokenSecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */

public class ProtectionOrderAssertionState extends AssertionState {

    boolean firstEvent = true;

    public ProtectionOrderAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        SPConstants.ProtectionOrder protectionOrder = ((SymmetricAsymmetricBindingBase) getAssertion()).getProtectionOrder();

        if (firstEvent) {
            firstEvent = false;
            //we have to invert the logic. When SignBeforeEncrypt is set then the Encryption token appears as first
            //in contrary if EncryptBeforeSign is set then the SignatureToken appears as first. So...:
            if (protectionOrder.equals(SPConstants.ProtectionOrder.SignBeforeEncrypting)
                    && securityEvent instanceof SignatureTokenSecurityEvent) {
                setAsserted(false);
                setErrorMessage("ProtectionOrder is " + SPConstants.ProtectionOrder.SignBeforeEncrypting + " but we got " + securityEvent.getSecurityEventType() + " first");
            } else if (protectionOrder.equals(SPConstants.ProtectionOrder.EncryptBeforeSigning)
                    && securityEvent instanceof EncryptionTokenSecurityEvent) {
                setAsserted(false);
                setErrorMessage("ProtectionOrder is " + SPConstants.ProtectionOrder.SignBeforeEncrypting + " but we got " + securityEvent.getSecurityEventType() + " first");
            }
        }
        return isAsserted();
    }
}
