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
import org.apache.xml.security.stax.securityEvent.AbstractSecuredElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * WSP1.3, 6.6 Entire Header and Body Signatures Property
 */
public class OnlySignEntireHeadersAndBodyAssertionState extends AssertionState implements Assertable {

    private String roleOrActor;

    public OnlySignEntireHeadersAndBodyAssertionState(AbstractSecurityAssertion assertion, boolean asserted, String roleOrActor) {
        super(assertion, asserted);
        this.roleOrActor = roleOrActor;
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SignedPart,
                WSSecurityEventConstants.SignedElement
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        AbstractSecuredElementSecurityEvent abstractSecuredElementSecurityEvent = (AbstractSecuredElementSecurityEvent) securityEvent;
        if (abstractSecuredElementSecurityEvent.isSigned() && !abstractSecuredElementSecurityEvent.isAttachment()) {
            List<QName> elementPath = abstractSecuredElementSecurityEvent.getElementPath();
            if (elementPath.size() == 4 && WSSUtils.isInSecurityHeader(abstractSecuredElementSecurityEvent.getXmlSecEvent(), elementPath, roleOrActor)) {
                setAsserted(true);
                return true;
            }
            if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                setAsserted(true);
                return true;
            }
            if (elementPath.size() == 2 && WSSUtils.isInSOAPBody(elementPath)) {
                setAsserted(true);
                return true;
            }
            setAsserted(false);
            setErrorMessage("OnlySignEntireHeadersAndBody not fulfilled, offending element: " + WSSUtils.pathAsString(elementPath));
            return false;
        }
        return true;
    }
}
