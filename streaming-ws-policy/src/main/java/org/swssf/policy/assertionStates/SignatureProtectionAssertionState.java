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

import org.apache.ws.secpolicy.AssertionState;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractSymmetricAsymmetricBinding;
import org.swssf.policy.Assertable;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.securityEvent.EncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureProtectionAssertionState extends AssertionState implements Assertable {

    private List<QName> elements = new ArrayList<QName>();

    public SignatureProtectionAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);

        elements.add(WSSConstants.TAG_dsig_Signature);
        elements.add(WSSConstants.TAG_wsse11_SignatureConfirmation);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.EncryptedElement
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
        AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) getAssertion();
        //todo better matching until we have a streaming xpath evaluation engine (work in progress)

        for (int i = 0; i < elements.size(); i++) {
            QName qName = elements.get(i);
            if (qName.equals(encryptedElementSecurityEvent.getElement())) {
                if (encryptedElementSecurityEvent.isEncrypted()) {
                    if (abstractSymmetricAsymmetricBinding.isEncryptSignature()) {
                        setAsserted(true);
                        return true;
                    } else {
                        setAsserted(false);
                        setErrorMessage("Element " + encryptedElementSecurityEvent.getElement() + " must not be encrypted");
                        return false;
                    }
                } else {
                    if (abstractSymmetricAsymmetricBinding.isEncryptSignature()) {
                        setAsserted(false);
                        setErrorMessage("Element " + encryptedElementSecurityEvent.getElement() + " must be encrypted");
                        return false;
                    } else {
                        setAsserted(true);
                        return true;
                    }
                }
            }
        }
        //if we return false here other encrypted elements will trigger a PolicyViolationException
        return true;
    }
}
