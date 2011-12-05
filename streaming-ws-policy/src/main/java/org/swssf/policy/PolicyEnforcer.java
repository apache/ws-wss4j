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
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.*;
import org.swssf.policy.assertionStates.*;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.*;

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
    private List<Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> assertionStateMap;
    private ArrayDeque<SecurityEvent> securityEventQueue = new ArrayDeque<SecurityEvent>();
    private boolean messageSignatureSecurityEventProcessed = false;
    private boolean messageEncryptionSecurityEventProcessed = false;
    private Map<String, TokenSecurityEvent> processedSecurityTokens = new HashMap<String, TokenSecurityEvent>();
    private boolean transportSecurityActive = false;

    public PolicyEnforcer(List<OperationPolicy> operationPolicies, String soapAction) throws WSSPolicyException {
        this.operationPolicies = operationPolicies;
        assertionStateMap = new ArrayList<Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>>>();

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

    /**
     * Precondition: Policy _must_ be normalized!
     */
    private void buildAssertionStateMap(
            PolicyComponent policyComponent,
            List<Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> assertionStateMap) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            int alternative = 0;
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                if (policyOperator instanceof ExactlyOne) {
                    assertionStateMap.add(new HashMap<SecurityEvent.Event, Map<Assertion, List<Assertable>>>());
                    buildAssertionStateMap(curPolicyComponent, assertionStateMap, alternative++);
                } else {
                    buildAssertionStateMap(curPolicyComponent, assertionStateMap);
                }
            }
        } else {
            throw new WSSPolicyException("Invalid PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }

    private void buildAssertionStateMap(
            PolicyComponent policyComponent,
            List<Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> assertionStateMap, int alternative) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                buildAssertionStateMap(curPolicyComponent, assertionStateMap, alternative);
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            List<Assertable> assertablesList = getAssertableForAssertion(abstractSecurityAssertion);
            for (int i = 0; i < assertablesList.size(); i++) {
                Assertable assertable = assertablesList.get(i);
                final Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(alternative);
                final SecurityEvent.Event[] securityEventType = assertable.getSecurityEventType();
                for (int j = 0; j < securityEventType.length; j++) {
                    SecurityEvent.Event event = securityEventType[j];
                    Map<Assertion, List<Assertable>> assertables = map.get(event);
                    if (assertables == null) {
                        assertables = new HashMap<Assertion, List<Assertable>>();
                        map.put(event, assertables);
                    }
                    addAssertionState(assertables, abstractSecurityAssertion, assertable);
                }
            }
        } else {
            throw new WSSPolicyException("Unsupported PolicyComponent: " + policyComponent + " type: " + policyComponent.getType());
        }
    }

    private void addAssertionState(Map<Assertion, List<Assertable>> assertables, Assertion keyAssertion, Assertable assertable) {
        List<Assertable> assertableList = assertables.get(keyAssertion);
        if (assertableList == null) {
            assertableList = new ArrayList<Assertable>();
            assertables.put(keyAssertion, assertableList);
        }
        assertableList.add(assertable);
    }

    protected List<Assertable> getAssertableForAssertion(AbstractSecurityAssertion abstractSecurityAssertion) throws WSSPolicyException {
        List<Assertable> assertableList = new ArrayList<Assertable>();
        //todo the initialState property can probably be eliminated
        if (abstractSecurityAssertion instanceof ContentEncryptedElements) {
            assertableList.add(new ContentEncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof EncryptedParts) {
            assertableList.add(new EncryptedPartsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof EncryptedElements) {
            assertableList.add(new EncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof SignedParts) {
            assertableList.add(new SignedPartsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof SignedElements) {
            assertableList.add(new SignedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof RequiredElements) {
            assertableList.add(new RequiredElementsAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof RequiredParts) {
            assertableList.add(new RequiredPartsAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof UsernameToken) {
            assertableList.add(new UsernameTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof IssuedToken) {
            assertableList.add(new IssuedTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof X509Token) {
            assertableList.add(new X509TokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof KerberosToken) {
            assertableList.add(new KerberosTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof SpnegoContextToken) {
            assertableList.add(new SpnegoContextTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof SecureConversationToken) {
            assertableList.add(new SecureConversationTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof SecurityContextToken) {
            assertableList.add(new SecurityContextTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof SamlToken) {
            assertableList.add(new SamlTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof RelToken) {
            assertableList.add(new RelTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof HttpsToken) {
            assertableList.add(new HttpsTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof KeyValueToken) {
            assertableList.add(new KeyValueTokenAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof AlgorithmSuite) {
            assertableList.add(new AlgorithmSuiteAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof AsymmetricBinding
                || abstractSecurityAssertion instanceof SymmetricBinding) {
            assertableList.add(new IncludeTimeStampAssertionState(abstractSecurityAssertion, false));
            assertableList.add(new ProtectionOrderAssertionState(abstractSecurityAssertion, false));
            assertableList.add(new SignatureProtectionAssertionState(abstractSecurityAssertion, false));
            //todo token protection
            assertableList.add(new OnlySignEntireHeadersAndBodyAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof TransportBinding) {
            assertableList.add(new IncludeTimeStampAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof Layout) {
            assertableList.add(new LayoutAssertionState(abstractSecurityAssertion, true));
        }
        return assertableList;
    }

    /**
     * tries to verify a SecurityEvent in realtime.
     *
     * @param securityEvent
     * @throws WSSPolicyException
     */
    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException {

        /*if (securityEvent instanceof TokenSecurityEvent
                && !(securityEvent instanceof HttpsTokenSecurityEvent)
                && !(securityEvent instanceof EncryptionTokenSecurityEvent)
                && !(securityEvent instanceof SignatureTokenSecurityEvent)) {
            //safety check: message tokens or supporting tokens are only allowed
            throw new WSSPolicyException("Illegal security event received: " + securityEvent.getSecurityEventType());
        }*/

        if (log.isDebugEnabled()) {
            log.debug("Verifying SecurityEvent: " + securityEvent.getSecurityEventType());
            if (securityEvent.getSecurityEventType() == SecurityEvent.Event.AlgorithmSuite) {
                log.debug("Algo: " + ((AlgorithmSuiteSecurityEvent) securityEvent).getAlgorithmURI());
                log.debug("KeyUsage: " + ((AlgorithmSuiteSecurityEvent) securityEvent).getKeyUsage());
            }
        }

        int notAssertedCount = 0;
        for (int i = 0; i < assertionStateMap.size(); i++) {
            Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(i);

            //every list entry counts as an alternative...
            Map<Assertion, List<Assertable>> assertionListMap = map.get(securityEvent.getSecurityEventType());
            if (assertionListMap != null && assertionListMap.size() > 0) {

                alternative:
                for (Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = assertionListMap.entrySet().iterator(); assertionStateIterator.hasNext(); ) {
                    Map.Entry<Assertion, List<Assertable>> assertionStateEntry = assertionStateIterator.next();
                    List<Assertable> assertionStates = assertionStateEntry.getValue();
                    for (int j = 0; j < assertionStates.size(); j++) {
                        Assertable assertable = assertionStates.get(j);
                        boolean asserted = assertable.assertEvent(securityEvent);
                        //...so if one fails, continue with the next map entry and increment the notAssertedCount
                        if (!asserted) {
                            notAssertedCount++;
                            break alternative;
                        }
                    }
                }
            }
        }
        //if the notAssertedCount equals the size of the list (the size of the list is equal to the alternatives)
        //then we could not satify any alternative
        if (notAssertedCount == assertionStateMap.size()) {
            logFailedAssertions();
            throw new PolicyViolationException("No policy alternative could be satisfied");
        }
    }

    /**
     * verifies the whole policy to try to find a satisfied alternative
     *
     * @throws WSSPolicyException       throws when the policy is invalid
     * @throws PolicyViolationException thrown when no alternative could be satisifed
     */
    private void verifyPolicy() throws WSSPolicyException {
        int notAsserted = 0;
        for (int i = 0; i < assertionStateMap.size(); i++) {
            Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(i);
            Iterator<Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> iterator = map.entrySet().iterator();
            alternative:
            while (iterator.hasNext()) {
                Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>> mapEntry = iterator.next();
                Iterator<Map.Entry<Assertion, List<Assertable>>> assertableIterator = mapEntry.getValue().entrySet().iterator();
                while (assertableIterator.hasNext()) {
                    Map.Entry<Assertion, List<Assertable>> assertionListEntry = assertableIterator.next();
                    List<Assertable> assertableList = assertionListEntry.getValue();
                    for (int j = 0; j < assertableList.size(); j++) {
                        Assertable assertable = assertableList.get(j);
                        if (!assertable.isAsserted()) {
                            notAsserted++;
                            continue alternative;
                        }
                    }
                }
            }
        }
        if (notAsserted == assertionStateMap.size()) {
            logFailedAssertions();
            throw new WSSPolicyException("No policy alternative could be satisfied");
        }
    }

    private void logFailedAssertions() {
        for (int i = 0; i < assertionStateMap.size(); i++) {
            Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(i);
            Set<Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> entrySet = map.entrySet();
            Iterator<Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> entryIterator = entrySet.iterator();
            while (entryIterator.hasNext()) {
                Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>> eventCollectionEntry = entryIterator.next();
                Map<Assertion, List<Assertable>> assertionListMap = eventCollectionEntry.getValue();
                for (Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateEntryIterator = assertionListMap.entrySet().iterator(); assertionStateEntryIterator.hasNext(); ) {
                    Map.Entry<Assertion, List<Assertable>> entry = assertionStateEntryIterator.next();
                    List<Assertable> assertionStates = entry.getValue();
                    for (int j = 0; j < assertionStates.size(); j++) {
                        Assertable assertable = assertionStates.get(j);
                        if (!assertable.isAsserted()) {
                            log.error(entry.getKey().getName() + " not satisfied: " + assertable.getErrorMessage());
                        }
                    }
                }
            }
        }
    }

    //multiple threads can call this method concurrently -> synchronize access
    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {

        //we do decide here if we have a message signature/encryption or a supporting signature/encryption
        //this information is not known in the WSS framework because it knows nothing
        //about the transportToken
        if (securityEvent instanceof TokenSecurityEvent) {
            final TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
            if (tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Signature) {
                if (!messageSignatureSecurityEventProcessed) {
                    messageSignatureSecurityEventProcessed = true;
                } else {
                    securityEvent = new SupportingTokenSecurityEvent(SecurityEvent.Event.SupportingToken, tokenSecurityEvent);
                }
                processedSecurityTokens.put(tokenSecurityEvent.getSecurityToken().getId(), tokenSecurityEvent);
            } else if (tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Encryption) {
                if (!messageEncryptionSecurityEventProcessed) {
                    messageEncryptionSecurityEventProcessed = true;
                } else {
                    securityEvent = new SupportingTokenSecurityEvent(SecurityEvent.Event.SupportingToken, tokenSecurityEvent);
                }
                processedSecurityTokens.put(tokenSecurityEvent.getSecurityToken().getId(), tokenSecurityEvent);
            }
        }
        if (securityEvent instanceof HttpsTokenSecurityEvent) {
            transportSecurityActive = true;
        }

        if (effectivePolicy != null) {
            //soap-action spoofing detection
            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                if (!effectivePolicy.getOperationName().equals(((OperationSecurityEvent) securityEvent).getOperation().getLocalPart())) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, new WSSPolicyException("SOAPAction (" + effectivePolicy.getOperationName() + ") does not match with the current Operation: " + ((OperationSecurityEvent) securityEvent).getOperation()));
                }
            }
            try {
                verifyPolicy(securityEvent);
            } catch (WSSPolicyException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
        } else {

            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                effectivePolicy = findPolicyBySOAPOperationName(operationPolicies, ((OperationSecurityEvent) securityEvent).getOperation().getLocalPart());
                if (effectivePolicy == null) {
                    //no policy to the operation given
                    effectivePolicy = new OperationPolicy("NoPolicyFoundForOperation");
                    effectivePolicy.setPolicy(new Policy());
                }
                try {
                    buildAssertionStateMap(effectivePolicy.getPolicy(), assertionStateMap);
                } catch (WSSPolicyException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }

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
                    try {
                        verifyPolicy(prevSecurityEvent);
                    } catch (WSSPolicyException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                    }
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
