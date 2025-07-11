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
package org.apache.wss4j.policy.stax.assertionStates;

import org.apache.wss4j.policy.AssertionState;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.api.stax.securityEvent.*;
import org.apache.wss4j.api.stax.utils.WSSUtils;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;

import javax.xml.namespace.QName;

import java.util.List;

/**
 * WSP1.3, 6.3 Protection Order Property
 */

public class ProtectionOrderAssertionState extends AssertionState implements Assertable {

    private PolicyAsserter policyAsserter;

    public ProtectionOrderAssertionState(AbstractSecurityAssertion assertion,
                                         PolicyAsserter policyAsserter,
                                         boolean asserted) {
        super(assertion, asserted);
        this.policyAsserter = policyAsserter;
        if (this.policyAsserter == null) {
            this.policyAsserter = new DummyPolicyAsserter();
        }

        if (asserted) {
            String namespace = getAssertion().getName().getNamespaceURI();
            AbstractSymmetricAsymmetricBinding.ProtectionOrder protectionOrder =
                ((AbstractSymmetricAsymmetricBinding) getAssertion()).getProtectionOrder();
            switch (protectionOrder) {  //NOPMD
            case SignBeforeEncrypting:
                policyAsserter.assertPolicy(new QName(namespace, SPConstants.SIGN_BEFORE_ENCRYPTING));
                break;
            case EncryptBeforeSigning:
                policyAsserter.assertPolicy(new QName(namespace, SPConstants.ENCRYPT_BEFORE_SIGNING));
                break;
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                SecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.EncryptedElement,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.ContentEncrypted,
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        AbstractSymmetricAsymmetricBinding.ProtectionOrder protectionOrder =
            ((AbstractSymmetricAsymmetricBinding) getAssertion()).getProtectionOrder();
        SecurityEventConstants.Event event = securityEvent.getSecurityEventType();
        if (WSSecurityEventConstants.SignedElement.equals(event)) {
            SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
            if (!signedElementSecurityEvent.isSigned()) {
                return true;
            }
            List<XMLSecurityConstants.ContentType> contentTypes = signedElementSecurityEvent.getProtectionOrder();
            testProtectionOrder(protectionOrder, contentTypes, signedElementSecurityEvent.getElementPath());
        } else if (WSSecurityEventConstants.SIGNED_PART.equals(event)) {
            SignedPartSecurityEvent signedPartSecurityEvent = (SignedPartSecurityEvent) securityEvent;
            if (!signedPartSecurityEvent.isSigned()) {
                return true;
            }
            List<XMLSecurityConstants.ContentType> contentTypes = signedPartSecurityEvent.getProtectionOrder();
            testProtectionOrder(protectionOrder, contentTypes, signedPartSecurityEvent.getElementPath());
        } else if (WSSecurityEventConstants.EncryptedElement.equals(event)) {
            EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
            if (!encryptedElementSecurityEvent.isEncrypted()) {
                return true;
            }
            List<XMLSecurityConstants.ContentType> contentTypes = encryptedElementSecurityEvent.getProtectionOrder();
            testProtectionOrder(protectionOrder, contentTypes, encryptedElementSecurityEvent.getElementPath());
        } else if (WSSecurityEventConstants.ENCRYPTED_PART.equals(event)) {
            EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
            if (!encryptedPartSecurityEvent.isEncrypted()) {
                return true;
            }
            List<XMLSecurityConstants.ContentType> contentTypes = encryptedPartSecurityEvent.getProtectionOrder();
            testProtectionOrder(protectionOrder, contentTypes, encryptedPartSecurityEvent.getElementPath());
        } else if (WSSecurityEventConstants.ContentEncrypted.equals(event)) {
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                (ContentEncryptedElementSecurityEvent) securityEvent;
            if (!contentEncryptedElementSecurityEvent.isEncrypted()) {
                return true;
            }
            List<XMLSecurityConstants.ContentType> contentTypes = contentEncryptedElementSecurityEvent.getProtectionOrder();
            testProtectionOrder(protectionOrder, contentTypes, contentEncryptedElementSecurityEvent.getElementPath());
        }
        return isAsserted();
    }

    private void testProtectionOrder(AbstractSymmetricAsymmetricBinding.ProtectionOrder protectionOrder,
                                     List<XMLSecurityConstants.ContentType> contentTypes, List<QName> elementPath) {
        String namespace = getAssertion().getName().getNamespaceURI();

        switch (protectionOrder) {  //NOPMD
            case SignBeforeEncrypting:
                int lastSignature = contentTypes.lastIndexOf(XMLSecurityConstants.ContentType.SIGNATURE);
                int firstEncryption = contentTypes.indexOf(XMLSecurityConstants.ContentType.ENCRYPTION);
                if (firstEncryption >= 0 && firstEncryption < lastSignature) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + protectionOrder + " but the " + WSSUtils.pathAsString(elementPath)
                        + " was encrypted and then signed");
                    policyAsserter.unassertPolicy(new QName(namespace, SPConstants.SIGN_BEFORE_ENCRYPTING),
                                                  getErrorMessage());
                } else {
                    policyAsserter.assertPolicy(new QName(namespace, SPConstants.SIGN_BEFORE_ENCRYPTING));
                }
                break;
            case EncryptBeforeSigning:
                int lastEncryption = contentTypes.lastIndexOf(XMLSecurityConstants.ContentType.ENCRYPTION);
                int firstSignature = contentTypes.indexOf(XMLSecurityConstants.ContentType.SIGNATURE);
                if (firstSignature >= 0 && firstSignature < lastEncryption) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + protectionOrder + " but the " + WSSUtils.pathAsString(elementPath)
                        + " was signed and then encrypted");
                    policyAsserter.unassertPolicy(new QName(namespace, SPConstants.ENCRYPT_BEFORE_SIGNING),
                                                  getErrorMessage());
                } else {
                    policyAsserter.assertPolicy(new QName(namespace, SPConstants.ENCRYPT_BEFORE_SIGNING));
                }
                break;
        }
    }
}
