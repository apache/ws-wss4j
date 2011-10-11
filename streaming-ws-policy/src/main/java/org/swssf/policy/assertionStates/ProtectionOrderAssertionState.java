/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.policy.assertionStates;

import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.policy.secpolicy.model.SymmetricAsymmetricBindingBase;
import org.swssf.wss.securityEvent.EncryptionTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignatureTokenSecurityEvent;

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
