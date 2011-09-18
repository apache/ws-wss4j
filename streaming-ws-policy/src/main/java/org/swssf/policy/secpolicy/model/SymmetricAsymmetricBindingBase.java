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

package org.swssf.policy.secpolicy.model;

import org.apache.neethi.Assertion;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.assertionStates.ProtectionOrderAssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public abstract class SymmetricAsymmetricBindingBase extends Binding {

    private SPConstants.ProtectionOrder protectionOrder = SPConstants.ProtectionOrder.SignBeforeEncrypting;

    private boolean signatureProtection;

    private boolean tokenProtection;

    private boolean entireHeadersAndBodySignatures;

    public SymmetricAsymmetricBindingBase(SPConstants spConstants) {
        super(spConstants);
    }

    /**
     * @return Returns the entireHeaderAndBodySignatures.
     */
    public boolean isEntireHeadersAndBodySignatures() {
        return entireHeadersAndBodySignatures;
    }

    /**
     * @param entireHeaderAndBodySignatures The entireHeaderAndBodySignatures to set.
     */
    public void setEntireHeadersAndBodySignatures(
            boolean entireHeaderAndBodySignatures) {
        this.entireHeadersAndBodySignatures = entireHeaderAndBodySignatures;
    }

    /**
     * @return Returns the protectionOrder.
     */

    public SPConstants.ProtectionOrder getProtectionOrder() {
        return protectionOrder;
    }

    /**
     * @param protectionOrder The protectionOrder to set.
     */
    public void setProtectionOrder(SPConstants.ProtectionOrder protectionOrder) {
        if (SPConstants.ProtectionOrder.EncryptBeforeSigning.equals(protectionOrder) ||
                SPConstants.ProtectionOrder.SignBeforeEncrypting.equals(protectionOrder)) {
            this.protectionOrder = protectionOrder;
        }
    }

    /**
     * @return Returns the signatureProtection.
     */
    public boolean isSignatureProtection() {
        return signatureProtection;
    }

    /**
     * @param signatureProtection The signatureProtection to set.
     */
    public void setSignatureProtection(boolean signatureProtection) {
        this.signatureProtection = signatureProtection;
    }

    /**
     * @return Returns the tokenProtection.
     */
    public boolean isTokenProtection() {
        return tokenProtection;
    }

    /**
     * @param tokenProtection The tokenProtection to set.
     */
    public void setTokenProtection(boolean tokenProtection) {
        this.tokenProtection = tokenProtection;
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        SecurityEvent.Event[] parentEvents = super.getResponsibleAssertionEvents();
        SecurityEvent.Event[] collectedSecurityEvents = new SecurityEvent.Event[parentEvents.length];
        System.arraycopy(parentEvents, 0, collectedSecurityEvents, 0, parentEvents.length);
        return collectedSecurityEvents;
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        super.getAssertions(assertionStateMap, operationPolicy);
        ProtectionOrderAssertionState protectionOrderAssertionState = new ProtectionOrderAssertionState(this, true);
        Map<Assertion, List<AssertionState>> assertionStates = assertionStateMap.get(SecurityEvent.Event.SignatureToken);
        addAssertionState(assertionStates, this, protectionOrderAssertionState);
        assertionStates = assertionStateMap.get(SecurityEvent.Event.EncryptionToken);
        addAssertionState(assertionStates, this, protectionOrderAssertionState);
    }

    @Override
    public boolean isAsserted(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) {
        boolean isAsserted = super.isAsserted(assertionStateMap);
        return isAsserted;
    }
}
