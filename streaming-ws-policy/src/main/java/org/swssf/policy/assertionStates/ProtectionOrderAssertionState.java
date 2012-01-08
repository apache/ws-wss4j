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
import org.swssf.wss.securityEvent.*;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class ProtectionOrderAssertionState extends AssertionState implements Assertable {

    private List<QName> signedElements = new ArrayList<QName>();
    private List<QName> encryptedElements = new ArrayList<QName>();

    public ProtectionOrderAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SignedElement,
                SecurityEvent.Event.SignedPart,
                SecurityEvent.Event.EncryptedElement,
                SecurityEvent.Event.EncryptedPart,
                SecurityEvent.Event.ContentEncrypted,
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        AbstractSymmetricAsymmetricBinding.ProtectionOrder protectionOrder = ((AbstractSymmetricAsymmetricBinding) getAssertion()).getProtectionOrder();
        setAsserted(true);
        switch (securityEvent.getSecurityEventType()) {
            case SignedElement:
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (!signedElementSecurityEvent.isSigned()) {
                    return true;
                }
                if (!encryptedElements.contains(signedElementSecurityEvent.getElement())) {
                    signedElements.add(signedElementSecurityEvent.getElement());
                } else {

                }
                System.out.println("Sig: " + signedElementSecurityEvent.getElement());
                break;
            case SignedPart:
                SignedPartSecurityEvent signedPartSecurityEvent = (SignedPartSecurityEvent) securityEvent;
                if (!signedPartSecurityEvent.isSigned()) {
                    return true;
                }
                System.out.println("Sig: " + signedPartSecurityEvent.getElement());
                break;
            case EncryptedElement:
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                if (!encryptedElementSecurityEvent.isEncrypted()) {
                    return true;
                }
                System.out.println("Enc: " + encryptedElementSecurityEvent.getElement() + " signed: " + encryptedElementSecurityEvent.isSignedContent());
                break;
            case EncryptedPart:
                EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                if (!encryptedPartSecurityEvent.isEncrypted()) {
                    return true;
                }
                System.out.println("Enc: " + encryptedPartSecurityEvent.getElement() + " signed: " + encryptedPartSecurityEvent.isSignedContent());
                break;
            case ContentEncrypted:
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;
                if (!contentEncryptedElementSecurityEvent.isEncrypted()) {
                    return true;
                }
                System.out.println("Enc: " + contentEncryptedElementSecurityEvent.getElement() + " signed: " + contentEncryptedElementSecurityEvent.isSignedContent());
                break;
        }


/*
        if (firstEvent) {
            firstEvent = false;
            //we have to invert the logic. When SignBeforeEncrypt is set then the Encryption token appears as first
            //in contrary if EncryptBeforeSign is set then the SignatureToken appears as first. So...:
            if (protectionOrder.equals(AbstractSymmetricAsymmetricBinding.ProtectionOrder.SignBeforeEncrypting)
                    && (tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Signature ||
                        tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.MainSignature)) {
                //setAsserted(false);
                setErrorMessage("ProtectionOrder is " + AbstractSymmetricAsymmetricBinding.ProtectionOrder.SignBeforeEncrypting + " but we got " + tokenSecurityEvent.getTokenUsage() + " first");
            } else if (protectionOrder.equals(AbstractSymmetricAsymmetricBinding.ProtectionOrder.EncryptBeforeSigning)
                    && (tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Encryption ||
                        tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.MainEncryption)) {
                //setAsserted(false);
                setErrorMessage("ProtectionOrder is " + AbstractSymmetricAsymmetricBinding.ProtectionOrder.EncryptBeforeSigning + " but we got " + tokenSecurityEvent.getTokenUsage() + " first");
            }
        }
*/
        return isAsserted();
    }
}
