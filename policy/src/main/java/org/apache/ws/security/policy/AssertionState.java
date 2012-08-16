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
package org.apache.ws.security.policy;

import org.apache.neethi.Assertion;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AssertionState {

    public enum State {
        INIT,
        HARD_FAILURE,
    }

    private State state = State.INIT;
    private boolean asserted;
    private boolean logged;
    private Assertion assertion;
    private StringBuilder errorMessage = new StringBuilder();

    public AssertionState(Assertion assertion, boolean initialAssertionState) {
        this.assertion = assertion;
        this.asserted = initialAssertionState;
    }

    public Assertion getAssertion() {
        return assertion;
    }

    public synchronized void setAsserted(boolean asserted) {
        //don't allow to toggle back once the assertion is explicitly marked as failed;
        if (this.state == State.HARD_FAILURE) {
            return;
        }
        if (!asserted) {
            this.state = State.HARD_FAILURE;
        }
        this.asserted = asserted;
    }

    public boolean isAsserted() {
        return asserted;
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

    public boolean isLogged() {
        return logged;
    }

    public void setLogged(boolean logged) {
        this.logged = logged;
    }
}
