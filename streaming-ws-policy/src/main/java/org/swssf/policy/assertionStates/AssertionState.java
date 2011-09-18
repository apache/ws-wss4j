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

import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.securityEvent.SecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AssertionState {

    private AbstractSecurityAssertion assertion;
    private boolean asserted;
    private StringBuilder errorMessage = new StringBuilder();

    public AssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        this.assertion = assertion;
        this.asserted = asserted;
    }

    public AbstractSecurityAssertion getAssertion() {
        return assertion;
    }

    public void setAsserted(boolean asserted) {
        this.asserted = asserted;
    }

    public boolean isAsserted() {
        return asserted;
    }

    public boolean assertEvent(SecurityEvent securityEvent) {
        if (securityEvent != null) {
            this.asserted = true;
        }
        return this.asserted;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage.append("\n").append(errorMessage);
    }

    public String getErrorMessage() {
        if (errorMessage.length() == 0) {
            return "Assertion " + assertion.getName() + " not satisfied";
        } else {
            return errorMessage.toString();
        }
    }
}
