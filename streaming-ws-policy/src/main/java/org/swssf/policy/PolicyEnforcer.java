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
package org.swssf.policy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.*;
import org.swssf.ext.WSSecurityException;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.WSSPolicyException;
import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.securityEvent.*;

import java.util.*;

/**
 * The PolicyEnforcer verifies the Policy assertions
 * The Assertion will be validated in realtime as far as possible
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyEnforcer implements SecurityEventListener {

    protected static final transient Log log = LogFactory.getLog(PolicyEnforcer.class);

    private List<OperationPolicy> operationPolicies;
    private OperationPolicy effectivePolicy;
    private Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap;
    private ArrayDeque<SecurityEvent> securityEventQueue = new ArrayDeque<SecurityEvent>();
    private boolean messageSignatureSecurityEventProcessed = false;
    private boolean messageEncryptionSecurityEventProcessed = false;
    private Map<String, TokenSecurityEvent> processedSecurityTokens = new HashMap<String, TokenSecurityEvent>();
    private boolean transportSecurityActive = false;

    public PolicyEnforcer(List<OperationPolicy> operationPolicies, String soapAction) throws WSSPolicyException {
        this.operationPolicies = operationPolicies;
        assertionStateMap = initAssertionStateMap();

        if (soapAction != null && !soapAction.equals("")) {
            effectivePolicy = findPolicyBySOAPAction(operationPolicies, soapAction);
            if (effectivePolicy != null) {
                buildAssertionStateMap(effectivePolicy.getPolicy(), assertionStateMap);
            }
        }
    }

    private OperationPolicy findPolicyBySOAPAction(List<OperationPolicy> operationPolicies, String soapAction) {
        for (int i = 0; i < operationPolicies.size(); i++) {
            OperationPolicy operationPolicy = operationPolicies.get(i);
            if (soapAction.equals(operationPolicy.getOperationAction())) {
                return operationPolicy;
            }
        }
        return null;
    }

    private OperationPolicy findPolicyBySOAPOperationName(List<OperationPolicy> operationPolicies, String soapOperationName) {
        for (int i = 0; i < operationPolicies.size(); i++) {
            OperationPolicy operationPolicy = operationPolicies.get(i);
            if (soapOperationName.equals(operationPolicy.getOperationName())) {
                return operationPolicy;
            }
        }
        return null;
    }

    private Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> initAssertionStateMap() {
        Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap = new HashMap<SecurityEvent.Event, Map<Assertion, List<AssertionState>>>();

        for (SecurityEvent.Event securityEvent : SecurityEvent.Event.values()) {
            assertionStateMap.put(securityEvent, new HashMap<Assertion, List<AssertionState>>());
        }

        return assertionStateMap;
    }

    private void buildAssertionStateMap(PolicyComponent policyComponent, Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                buildAssertionStateMap(curPolicyComponent, assertionStateMap);
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            abstractSecurityAssertion.getAssertions(assertionStateMap, effectivePolicy);
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }

    /**
     * tries to verify a SecurityEvent in realtime.
     *
     * @param securityEvent
     * @throws WSSPolicyException
     */
    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException {

        if (securityEvent instanceof TokenSecurityEvent
                && !(securityEvent instanceof HttpsTokenSecurityEvent)
                && !(securityEvent instanceof EncryptionTokenSecurityEvent)
                && !(securityEvent instanceof SignatureTokenSecurityEvent)) {
            //safety check: message tokens or supporting tokens are only allowed
            throw new WSSPolicyException("Illegal security event received: " + securityEvent);
        }

        if (log.isDebugEnabled()) {
            log.debug("Verifying SecurityEvent: " + securityEvent.getSecurityEventType());
            if (securityEvent.getSecurityEventType() == SecurityEvent.Event.AlgorithmSuite) {
                log.debug("Algo: " + ((AlgorithmSuiteSecurityEvent) securityEvent).getAlgorithmURI());
                log.debug("KeyUsage: " + ((AlgorithmSuiteSecurityEvent) securityEvent).getKeyUsage());
            }
        }


        Map<Assertion, List<AssertionState>> assertionListMap = assertionStateMap.get(securityEvent.getSecurityEventType());
        if (assertionListMap != null && assertionListMap.size() > 0) {
            int notAssertedCount = 0;
            //every map entry counts as an alternative...
            for (Iterator<Map.Entry<Assertion, List<AssertionState>>> assertionStateIterator = assertionListMap.entrySet().iterator(); assertionStateIterator.hasNext(); ) {
                Map.Entry<Assertion, List<AssertionState>> assertionStateEntry = assertionStateIterator.next();
                List<AssertionState> assertionStates = assertionStateEntry.getValue();
                for (int i = 0; i < assertionStates.size(); i++) {
                    AssertionState assertionState = assertionStates.get(i);
                    boolean asserted = assertionState.assertEvent(securityEvent);
                    //...so if one fails, continue with the next map entry and increment the notAssertedCount
                    if (!asserted) {
                        notAssertedCount++;
                        break;
                    }
                }
            }
            //if the notAssertedCount equals the size of the map (the size of the map is equal to the alternatives)
            //then we could not satify any alternative
            if (notAssertedCount == assertionListMap.size()) {
                logFailedAssertions();
                throw new PolicyViolationException("No policy alternative could be satisfied");
            }
        }
    }

    /**
     * verifies the whole policy to try to find a satisfied alternative
     *
     * @throws WSSPolicyException       throws when the policy is invalid
     * @throws PolicyViolationException thrown when no alternative could be satisifed
     */
    private void verifyPolicy() throws WSSPolicyException {
        boolean isAsserted = verifyPolicy(effectivePolicy.getPolicy());
        if (!isAsserted) {
            logFailedAssertions();
            throw new PolicyViolationException("No policy alternative could be satisfied");
        }
    }

    private boolean verifyPolicy(PolicyComponent policyComponent) throws WSSPolicyException {

        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            boolean isExactlyOne = policyOperator instanceof ExactlyOne;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();

            boolean isAsserted = false;
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                //recursive call until a satistfied alternative is found
                isAsserted = verifyPolicy(curPolicyComponent);
                if (isExactlyOne && isAsserted) {
                    return true; //a satisfied alternative is found
                } else if (!isExactlyOne && !isAsserted) {
                    return false;
                }
            }
            return isAsserted;
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            return abstractSecurityAssertion.isAsserted(assertionStateMap);
        } else if (policyComponent == null) {
            throw new WSSPolicyException("Policy not found");
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }

    private void logFailedAssertions() {
        Set<Map.Entry<SecurityEvent.Event, Map<Assertion, List<AssertionState>>>> entrySet = assertionStateMap.entrySet();
        Iterator<Map.Entry<SecurityEvent.Event, Map<Assertion, List<AssertionState>>>> entryIterator = entrySet.iterator();
        while (entryIterator.hasNext()) {
            Map.Entry<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> eventCollectionEntry = entryIterator.next();
            Map<Assertion, List<AssertionState>> assertionStates = eventCollectionEntry.getValue();
            for (Iterator<Map.Entry<Assertion, List<AssertionState>>> assertionStateEntryIterator = assertionStates.entrySet().iterator(); assertionStateEntryIterator.hasNext(); ) {
                Map.Entry<Assertion, List<AssertionState>> entry = assertionStateEntryIterator.next();
                List<AssertionState> assertionState = entry.getValue();
                for (int i = 0; i < assertionState.size(); i++) {
                    AssertionState state = assertionState.get(i);
                    log.error(state.getErrorMessage());
                }
            }
        }
    }

    //multiple threads can call this method concurrently -> synchronize access
    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {

        //we do decide here if we have a message signature/encryption or a supporting signature/encryption
        //this information is not known in the WSS framework because it knows nothing
        //about the transportToken
        if (securityEvent.getSecurityEventType() == SecurityEvent.Event.TransportToken
                || securityEvent.getSecurityEventType() == SecurityEvent.Event.SignatureToken) {
            final TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
            if (!messageSignatureSecurityEventProcessed) {
                messageSignatureSecurityEventProcessed = true;
            } else {
                securityEvent = new SupportingTokenSecurityEvent(SecurityEvent.Event.SupportingToken, tokenSecurityEvent);
            }
            processedSecurityTokens.put(tokenSecurityEvent.getSecurityToken().getId(), tokenSecurityEvent);
        }
        if (securityEvent.getSecurityEventType() == SecurityEvent.Event.TransportToken
                || securityEvent.getSecurityEventType() == SecurityEvent.Event.EncryptionToken) {
            final TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
            if (!messageEncryptionSecurityEventProcessed) {
                messageEncryptionSecurityEventProcessed = true;
            } else {
                securityEvent = new SupportingTokenSecurityEvent(SecurityEvent.Event.SupportingToken, tokenSecurityEvent);
            }
            processedSecurityTokens.put(tokenSecurityEvent.getSecurityToken().getId(), tokenSecurityEvent);
        }
        if (securityEvent.getSecurityEventType() == SecurityEvent.Event.TransportToken) {
            transportSecurityActive = true;
        }

        if (effectivePolicy != null) {
            //soap-action spoofing detection
            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                if (!effectivePolicy.getOperationName().equals(((OperationSecurityEvent) securityEvent).getOperation().getLocalPart())) {
                    throw new WSSPolicyException("SOAPAction (" + effectivePolicy.getOperationName() + ") does not match with the current Operation: " + ((OperationSecurityEvent) securityEvent).getOperation());
                }
            }
            verifyPolicy(securityEvent);
        } else {

            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                effectivePolicy = findPolicyBySOAPOperationName(operationPolicies, ((OperationSecurityEvent) securityEvent).getOperation().getLocalPart());
                if (effectivePolicy == null) {
                    //no policy to the operation given
                    effectivePolicy = new OperationPolicy("NoPolicyFoundForOperation");
                    effectivePolicy.setPolicy(new Policy());
                }
                buildAssertionStateMap(effectivePolicy.getPolicy(), assertionStateMap);

                Iterator<SecurityEvent> securityEventIterator = securityEventQueue.descendingIterator();
                while (securityEventIterator.hasNext()) {
                    SecurityEvent prevSecurityEvent = securityEventIterator.next();

                    if (prevSecurityEvent instanceof TokenSecurityEvent) {
                        final TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) prevSecurityEvent;
                        String id = tokenSecurityEvent.getSecurityToken().getId();
                        if (!processedSecurityTokens.containsKey(id)) {
                            prevSecurityEvent = new SupportingTokenSecurityEvent(SecurityEvent.Event.SupportingToken, tokenSecurityEvent);
                            processedSecurityTokens.put(id, tokenSecurityEvent);
                        }
                    }
                    verifyPolicy(prevSecurityEvent);
                }

            } else {
                //queue event until policy is resolved
                securityEventQueue.push(securityEvent);
            }
        }
    }

    /**
     * the final Policy validation to find a satisfied alternative
     *
     * @throws PolicyViolationException if no alternative could be satisfied
     */
    public void doFinal() throws WSSPolicyException {
        verifyPolicy();
    }

    public boolean isTransportSecurityActive() {
        return transportSecurityActive;
    }
}
