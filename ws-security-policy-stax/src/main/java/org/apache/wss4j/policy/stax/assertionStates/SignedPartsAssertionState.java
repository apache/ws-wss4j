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
import org.apache.wss4j.policy.model.Header;
import org.apache.wss4j.policy.model.SignedParts;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.utils.WSSUtils;

import javax.xml.namespace.QName;

import java.util.LinkedList;
import java.util.List;

/**
 * WSP1.3, 4.1.1 SignedParts Assertion
 */
public class SignedPartsAssertionState extends AssertionState implements Assertable {

    private int attachmentCount;
    private int signedAttachmentCount;
    private boolean signedAttachmentRequired;
    private PolicyAsserter policyAsserter;
    private final boolean soap12;

    public SignedPartsAssertionState(
        AbstractSecurityAssertion assertion, PolicyAsserter policyAsserter,
        boolean asserted, int attachmentCount, boolean soap12
    ) {
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
                WSSecurityEventConstants.SIGNED_PART
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {

        SignedPartSecurityEvent signedPartSecurityEvent = (SignedPartSecurityEvent) securityEvent;
        SignedParts signedParts = (SignedParts) getAssertion();

        if (signedParts.getAttachments() != null) {
            signedAttachmentRequired = true;
            if (signedPartSecurityEvent.isAttachment()) {
                signedAttachmentCount++;
                setAsserted(true);
                policyAsserter.assertPolicy(getAssertion());
                return true;
            }
        }

        List<QName> bodyPath = soap12 ? WSSConstants.SOAP_12_BODY_PATH : WSSConstants.SOAP_11_BODY_PATH;
        if (signedParts.isBody()
                && WSSUtils.pathMatches(bodyPath, signedPartSecurityEvent.getElementPath())) {
            if (signedPartSecurityEvent.isSigned()) {
                setAsserted(true);
                policyAsserter.assertPolicy(getAssertion());
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + WSSUtils.pathAsString(signedPartSecurityEvent.getElementPath()) + " must be signed");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                return false;
            }
        }
        //body processed above. so this must be a header element
        if (signedParts.isSignAllHeaders()) {
            if (signedPartSecurityEvent.isSigned()) {
                setAsserted(true);
                policyAsserter.assertPolicy(getAssertion());
                return true;
            } else {
                setAsserted(false);
                setErrorMessage("Element " + WSSUtils.pathAsString(signedPartSecurityEvent.getElementPath()) + " must be signed");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                return false;
            }
        } else {
            for (int i = 0; i < signedParts.getHeaders().size(); i++) {
                Header header = signedParts.getHeaders().get(i);
                QName headerQName = new QName(header.getNamespace(), header.getName() == null ? "" : header.getName());

                List<QName> headerPath = new LinkedList<>();
                if (soap12) {
                    headerPath.addAll(WSSConstants.SOAP_12_HEADER_PATH);
                } else {
                    headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
                }
                headerPath.add(headerQName);

                if (WSSUtils.pathMatches(headerPath, signedPartSecurityEvent.getElementPath(), header.getName() == null)) {
                    if (signedPartSecurityEvent.isSigned()) {
                        setAsserted(true);
                        policyAsserter.assertPolicy(getAssertion());
                        return true;
                    } else {
                        setAsserted(false);
                        setErrorMessage("Element " + WSSUtils.pathAsString(signedPartSecurityEvent.getElementPath()) + " must be signed");
                        policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                        return false;
                    }
                }
            }
        }

        //if we return false here other signed elements will trigger a PolicyViolationException
        policyAsserter.assertPolicy(getAssertion());
        return true;
    }

    @Override
    public boolean isAsserted() {
        if (signedAttachmentRequired && signedAttachmentCount < attachmentCount) {
            return false;
        }
        return super.isAsserted();
    }
}
