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
import org.apache.ws.secpolicy.model.EncryptedParts;
import org.apache.ws.secpolicy.model.Header;
import org.swssf.policy.Assertable;
import org.swssf.policy.PolicyConstants;
import org.swssf.wss.securityEvent.EncryptedPartSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedPartsAssertionState extends AssertionState implements Assertable {

    public EncryptedPartsAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.EncryptedPart
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {

        //todo attachments

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
        EncryptedParts encryptedParts = (EncryptedParts) getAssertion();

        if (encryptedParts.isBody() && (encryptedPartSecurityEvent.getElement().equals(PolicyConstants.TAG_soap11_Body)
                || encryptedPartSecurityEvent.getElement().equals(PolicyConstants.TAG_soap12_Body))) {
            if (encryptedPartSecurityEvent.isEncrypted()) {
                setAsserted(true);
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + encryptedPartSecurityEvent.getElement() + " must be encrypted");
                return false;
            }
        }
        //body processed above. so this must be a header element
        for (int i = 0; i < encryptedParts.getHeaders().size(); i++) {
            Header header = encryptedParts.getHeaders().get(i);
            if (header.getNamespace().equals(encryptedPartSecurityEvent.getElement().getNamespaceURI())
                    && (header.getName() == null //== wildcard
                    || header.getName().equals(encryptedPartSecurityEvent.getElement().getLocalPart()))) {
                if (encryptedPartSecurityEvent.isEncrypted()) {
                    setAsserted(true);
                    return true;
                } else {
                    setErrorMessage("Element " + encryptedPartSecurityEvent.getElement() + " must be encrypted");
                    return false;
                }
            }
        }

        //if we return false here other encrypted elements will trigger a PolicyViolationException
        return true;
    }
}
