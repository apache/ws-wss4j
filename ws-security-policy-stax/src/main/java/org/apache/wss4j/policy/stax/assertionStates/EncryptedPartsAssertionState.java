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
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.EncryptedParts;
import org.apache.wss4j.policy.model.Header;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.utils.WSSUtils;

import javax.xml.namespace.QName;

import java.util.LinkedList;
import java.util.List;

/**
 * WSP1.3, 4.2.1 EncryptedParts Assertion
 */
public class EncryptedPartsAssertionState extends AssertionState implements Assertable {

    private int attachmentCount;
    private int encryptedAttachmentCount;
    private boolean encryptedAttachmentRequired;
    private PolicyAsserter policyAsserter;
    private final boolean soap12;

    public EncryptedPartsAssertionState(
        AbstractSecurityAssertion assertion,
        PolicyAsserter policyAsserter,
        boolean asserted, int attachmentCount, boolean soap12) {
        super(assertion, asserted);
        this.attachmentCount = attachmentCount;

        this.policyAsserter = policyAsserter;
        if (this.policyAsserter == null) {
            this.policyAsserter = new DummyPolicyAsserter();
        }

        if (asserted) {
            policyAsserter.assertPolicy(getAssertion());
        }

        this.soap12 = soap12;
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.ENCRYPTED_PART
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
        EncryptedParts encryptedParts = (EncryptedParts) getAssertion();

        if (encryptedParts.getAttachments() != null) {
            encryptedAttachmentRequired = true;
            if (encryptedPartSecurityEvent.isAttachment()) {
                encryptedAttachmentCount++;
                setAsserted(true);
                policyAsserter.assertPolicy(getAssertion());
                return true;
            }
        }

        //we'll never get events with the exact body path but child elements so we can just check if we are in the body
        if (encryptedParts.isBody() && WSSUtils.isInSOAPBody(encryptedPartSecurityEvent.getElementPath())) {
            if (encryptedPartSecurityEvent.isEncrypted()) {
                setAsserted(true);
                policyAsserter.assertPolicy(getAssertion());
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("SOAP-Body must be encrypted");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                return false;
            }
        }
        //body processed above. so this must be a header element
        for (int i = 0; i < encryptedParts.getHeaders().size(); i++) {
            Header header = encryptedParts.getHeaders().get(i);
            QName headerQName = new QName(header.getNamespace(), header.getName() == null ? "" : header.getName());

            List<QName> headerPath = new LinkedList<>();
            if (soap12) {
                headerPath.addAll(WSSConstants.SOAP_12_HEADER_PATH);
            } else {
                headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
            }
            headerPath.add(headerQName);

            if (WSSUtils.pathMatches(headerPath, encryptedPartSecurityEvent.getElementPath(), header.getName() == null)) {
                if (encryptedPartSecurityEvent.isEncrypted()) {
                    setAsserted(true);
                    policyAsserter.assertPolicy(getAssertion());
                    return true;
                } else {
                    setAsserted(false);
                    setErrorMessage("Element " + WSSUtils.pathAsString(encryptedPartSecurityEvent.getElementPath()) + " must be encrypted");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                    return false;
                }
            }
        }

        //if we return false here other encrypted elements will trigger a PolicyViolationException
        policyAsserter.assertPolicy(getAssertion());
        return true;
    }

    @Override
    public boolean isAsserted() {
        if (encryptedAttachmentRequired && encryptedAttachmentCount < attachmentCount) {
            return false;
        }
        return super.isAsserted();
    }
}
