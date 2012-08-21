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
package org.apache.ws.security.policy.stax;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.*;
import org.apache.neethi.builders.PrimitiveAssertion;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.ws.security.policy.model.*;
import org.apache.ws.security.policy.stax.assertionStates.*;
import org.apache.ws.security.stax.wss.ext.WSSConstants;
import org.apache.ws.security.stax.wss.securityEvent.OperationSecurityEvent;
import org.apache.ws.security.stax.wss.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.xml.namespace.QName;
import java.util.*;

/**
 * The PolicyEnforcer verifies the Policy assertions
 * The Assertion will be validated in realtime as far as possible
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyEnforcer implements SecurityEventListener {

    //todo:
    // AlgorithmSuite SoapNorm
    // AlgorithmSuite STR Trans
    // AlgorithmSuite XPath
    // AlgorithmSuite Comp Key
    // Layout? I don't know if it is that relevant and worth. We need security header element numbering
    //to implement it.
    // HttpsToken Algorithms
    //unused tokens must be checked (algorithms etc)

    protected static final transient Log log = LogFactory.getLog(PolicyEnforcer.class);

    private final List<OperationPolicy> operationPolicies;
    private OperationPolicy effectivePolicy;
    private final List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMap;
    private final List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> failedAssertionStateMap;

    private final Deque<SecurityEvent> securityEventQueue = new LinkedList<SecurityEvent>();
    private boolean operationSecurityEventOccured = false;

    public PolicyEnforcer(List<OperationPolicy> operationPolicies, String soapAction) throws WSSPolicyException {
        this.operationPolicies = operationPolicies;
        assertionStateMap = new LinkedList<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>>();
        failedAssertionStateMap = new LinkedList<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>>();

        if (soapAction != null && !soapAction.isEmpty()) {
            effectivePolicy = findPolicyBySOAPAction(operationPolicies, soapAction);
            if (effectivePolicy != null) {
                buildAssertionStateMap(effectivePolicy.getPolicy(), assertionStateMap);
            }
        }
    }

    private OperationPolicy findPolicyBySOAPAction(List<OperationPolicy> operationPolicies, String soapAction) {
        Iterator<OperationPolicy> operationPolicyIterator = operationPolicies.iterator();
        while (operationPolicyIterator.hasNext()) {
            OperationPolicy operationPolicy = operationPolicyIterator.next();
            if (soapAction.equals(operationPolicy.getOperationAction())) {
                return operationPolicy;
            }
        }
        return null;
    }

    private OperationPolicy findPolicyBySOAPOperationName(List<OperationPolicy> operationPolicies, String soapOperationName) {
        Iterator<OperationPolicy> operationPolicyIterator = operationPolicies.iterator();
        while (operationPolicyIterator.hasNext()) {
            OperationPolicy operationPolicy = operationPolicyIterator.next();
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
            List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMap) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            int alternative = 0;
            Iterator<PolicyComponent> policyComponentIterator = policyComponents.iterator();
            while (policyComponentIterator.hasNext()) {
                PolicyComponent curPolicyComponent = policyComponentIterator.next();
                if (policyOperator instanceof ExactlyOne) {
                    assertionStateMap.add(new HashMap<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>());
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
            List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMap, int alternative) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            Iterator<PolicyComponent> policyComponentIterator = policyComponents.iterator();
            while (policyComponentIterator.hasNext()) {
                PolicyComponent curPolicyComponent = policyComponentIterator.next();
                buildAssertionStateMap(curPolicyComponent, assertionStateMap, alternative);
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            List<Assertable> assertablesList = getAssertableForAssertion(abstractSecurityAssertion);
            Iterator<Assertable> assertableIterator = assertablesList.iterator();
            while (assertableIterator.hasNext()) {
                Assertable assertable = assertableIterator.next();
                final Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(alternative);
                final SecurityEventConstants.Event[] securityEventType = assertable.getSecurityEventType();
                for (int j = 0; j < securityEventType.length; j++) {
                    SecurityEventConstants.Event event = securityEventType[j];
                    Map<Assertion, List<Assertable>> assertables = map.get(event);
                    if (assertables == null) {
                        assertables = new HashMap<Assertion, List<Assertable>>();
                        map.put(event, assertables);
                    }
                    addAssertionState(assertables, abstractSecurityAssertion, assertable);
                }
            }
            if (abstractSecurityAssertion instanceof PolicyContainingAssertion) {
                buildAssertionStateMap(((PolicyContainingAssertion) abstractSecurityAssertion).getPolicy(), assertionStateMap, alternative);
            }
        } else if (policyComponent instanceof PrimitiveAssertion) {
            //nothing to-do. should be covered by the surrounding assertion
        } else {
            throw new WSSPolicyException("Unsupported PolicyComponent: " + policyComponent + " type: " + policyComponent.getType());
        }
    }

    private void addAssertionState(Map<Assertion, List<Assertable>> assertables, Assertion keyAssertion, Assertable assertable) {
        List<Assertable> assertableList = assertables.get(keyAssertion);
        if (assertableList == null) {
            assertableList = new LinkedList<Assertable>();
            assertables.put(keyAssertion, assertableList);
        }
        assertableList.add(assertable);
    }

    protected List<Assertable> getAssertableForAssertion(AbstractSecurityAssertion abstractSecurityAssertion) throws WSSPolicyException {
        List<Assertable> assertableList = new LinkedList<Assertable>();
        if (abstractSecurityAssertion instanceof ContentEncryptedElements) {
            //initialized with asserted=true because it could be that parent elements are encrypted and therefore these element are also encrypted
            //the test if it is really encrypted is done via the PolicyInputProcessor which emits EncryptedElementEvents for unencrypted elements with the unencrypted flag
            assertableList.add(new ContentEncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof EncryptedParts) {
            //initialized with asserted=true with the same reason as by the EncryptedParts above
            assertableList.add(new EncryptedPartsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof EncryptedElements) {
            //initialized with asserted=true with the same reason as by the EncryptedParts above
            assertableList.add(new EncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof SignedParts) {
            //initialized with asserted=true because it could be that parent elements are signed and therefore these element are also signed
            //the test if it is really signed is done via the PolicyInputProcessor which emits SignedElementEvents for unsigned elements with the unsigned flag
            assertableList.add(new SignedPartsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof SignedElements) {
            //initialized with asserted=true with the same reason as by the SignedParts above
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
            //initialized with asserted=true because we do negative matching
            assertableList.add(new AlgorithmSuiteAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof AsymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof SymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof TransportBinding) {
        } /*else if (abstractSecurityAssertion instanceof Layout) {
            assertableList.add(new LayoutAssertionState(abstractSecurityAssertion, true));
        }*/

        if (abstractSecurityAssertion instanceof AbstractBinding) {
            AbstractBinding abstractBinding = (AbstractBinding) abstractSecurityAssertion;
            if (abstractBinding instanceof AbstractSymmetricAsymmetricBinding) {
                AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) abstractSecurityAssertion;
                assertableList.add(new ProtectionOrderAssertionState(abstractSymmetricAsymmetricBinding, true));
                assertableList.add(new SignatureProtectionAssertionState(abstractSymmetricAsymmetricBinding, true));
                if (abstractSymmetricAsymmetricBinding.isOnlySignEntireHeadersAndBody()) {
                    assertableList.add(new OnlySignEntireHeadersAndBodyAssertionState(abstractSecurityAssertion, false));
                }
                assertableList.add(new TokenProtectionAssertionState(abstractSecurityAssertion, true));
            }

            //WSP1.3, 6.2 Timestamp Property
            assertableList.add(new IncludeTimeStampAssertionState(abstractBinding, true));
            if (abstractBinding.isIncludeTimestamp()) {
                RequiredElementsAssertionState requiredElementsAssertionState = new RequiredElementsAssertionState(abstractBinding, false);
                List<QName> timestampElementPath = new LinkedList<QName>();
                timestampElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
                timestampElementPath.add(WSSConstants.TAG_wsu_Timestamp);
                requiredElementsAssertionState.addElement(timestampElementPath);
                assertableList.add(requiredElementsAssertionState);

                SignedElementsAssertionState signedElementsAssertionState = new SignedElementsAssertionState(abstractSecurityAssertion, true);
                signedElementsAssertionState.addElement(timestampElementPath);
                assertableList.add(signedElementsAssertionState);
            }
        }

        return assertableList;
    }

    /**
     * tries to verify a SecurityEvent in realtime.
     *
     * @param securityEvent
     * @throws WSSPolicyException
     */
    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException, XMLSecurityException {
        {
            //We have to check the failed assertions for logging purposes firstly...
            Iterator<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMapIterator = this.failedAssertionStateMap.iterator();
            alternative:
            while (assertionStateMapIterator.hasNext()) {
                Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMapIterator.next();
                //every list entry counts as an alternative...
                Map<Assertion, List<Assertable>> assertionListMap = map.get(securityEvent.getSecurityEventType());
                if (assertionListMap != null && assertionListMap.size() > 0) {
                    Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = assertionListMap.entrySet().iterator();
                    while (assertionStateIterator.hasNext()) {
                        Map.Entry<Assertion, List<Assertable>> assertionStateEntry = assertionStateIterator.next();
                        List<Assertable> assertionStates = assertionStateEntry.getValue();
                        Iterator<Assertable> assertableIterator = assertionStates.iterator();
                        while (assertableIterator.hasNext()) {
                            Assertable assertable = assertableIterator.next();
                            boolean asserted = assertable.assertEvent(securityEvent);
                            //...so if one fails, continue with the next map entry and increment the notAssertedCount
                            if (!asserted) {
                                continue alternative;
                            }
                        }
                    }
                }
            }
        }

        String assertionMessage = null;
        {
            //...and then check the remaining alternatives
            Iterator<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMapIterator = this.assertionStateMap.iterator();
            //every map entry counts as an alternative...
            alternative:
            while (assertionStateMapIterator.hasNext()) {
                Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMapIterator.next();
                Map<Assertion, List<Assertable>> assertionListMap = map.get(securityEvent.getSecurityEventType());
                if (assertionListMap != null && assertionListMap.size() > 0) {
                    Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = assertionListMap.entrySet().iterator();
                    while (assertionStateIterator.hasNext()) {
                        Map.Entry<Assertion, List<Assertable>> assertionStateEntry = assertionStateIterator.next();
                        List<Assertable> assertionStates = assertionStateEntry.getValue();
                        Iterator<Assertable> assertableIterator = assertionStates.iterator();
                        while (assertableIterator.hasNext()) {
                            Assertable assertable = assertableIterator.next();
                            boolean asserted = assertable.assertEvent(securityEvent);
                            //...so if one fails, continue with the next map entry and increment the notAssertedCount
                            if (!asserted) {
                                assertionMessage = assertable.getErrorMessage();
                                failedAssertionStateMap.add(map);
                                assertionStateMapIterator.remove();
                                continue alternative;
                            }
                        }
                    }
                }
            }
        }
        //if the assertionStateMap is empty (the size of the list is equal to the alternatives)
        //then we could not satisfy any alternative
        if (assertionStateMap.isEmpty()) {
            logFailedAssertions();
            throw new PolicyViolationException(assertionMessage);
        }
    }

    /**
     * verifies the whole policy to try to find a satisfied alternative
     *
     * @throws WSSPolicyException       throws when the policy is invalid
     * @throws PolicyViolationException thrown when no alternative could be satisifed
     */
    private void verifyPolicy() throws WSSPolicyException {
        String assertionMessage = null;
        Iterator<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMapIterator = this.assertionStateMap.iterator();
        alternative:
        while (assertionStateMapIterator.hasNext()) {
            Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMapIterator.next();
            Iterator<Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> mapEntry = iterator.next();
                Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = mapEntry.getValue().entrySet().iterator();
                while (assertionStateIterator.hasNext()) {
                    Map.Entry<Assertion, List<Assertable>> assertionListEntry = assertionStateIterator.next();
                    List<Assertable> assertableList = assertionListEntry.getValue();
                    Iterator<Assertable> assertableIterator = assertableList.iterator();
                    while (assertableIterator.hasNext()) {
                        Assertable assertable = assertableIterator.next();
                        if (!assertable.isAsserted()) {
                            assertionMessage = assertable.getErrorMessage();
                            failedAssertionStateMap.add(map);
                            assertionStateMapIterator.remove();
                            continue alternative;
                        }
                    }
                }
            }
        }
        if (assertionStateMap.isEmpty()) {
            logFailedAssertions();
            throw new WSSPolicyException(assertionMessage);
        }
    }

    /**
     * verifies the policy after the OperationSecurityEvent occurred. This allows to
     * stop further processing after the header is processed when the policy is not fulfilled.
     *
     * @throws WSSPolicyException       throws when the policy is invalid
     * @throws PolicyViolationException thrown when no alternative could be satisfied
     */
    private void verifyPolicyAfterOperationSecurityEvent() throws WSSPolicyException {
        String assertionMessage = null;
        Iterator<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMapIterator = this.assertionStateMap.iterator();
        alternative:
        while (assertionStateMapIterator.hasNext()) {
            Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMapIterator.next();
            Iterator<Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> mapEntry = iterator.next();
                Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = mapEntry.getValue().entrySet().iterator();
                while (assertionStateIterator.hasNext()) {
                    Map.Entry<Assertion, List<Assertable>> assertionListEntry = assertionStateIterator.next();
                    List<Assertable> assertableList = assertionListEntry.getValue();
                    Iterator<Assertable> assertableIterator = assertableList.iterator();
                    while (assertableIterator.hasNext()) {
                        Assertable assertable = assertableIterator.next();

                        boolean doAssert = false;
                        if (assertable instanceof TokenAssertionState) {
                            TokenAssertionState tokenAssertionState = (TokenAssertionState) assertable;
                            AbstractToken abstractToken = (AbstractToken) tokenAssertionState.getAssertion();
                            AbstractSecurityAssertion assertion = abstractToken.getParentAssertion();
                            if (assertion instanceof SupportingTokens) {
                                doAssert = true;
                            }
                        } else if (assertable instanceof TokenProtectionAssertionState) {
                            doAssert = true;
                        }

                        if (doAssert && !assertable.isAsserted()) {
                            assertionMessage = assertable.getErrorMessage();
                            failedAssertionStateMap.add(map);
                            assertionStateMapIterator.remove();
                            continue alternative;
                        }
                    }
                }
            }
        }
        if (assertionStateMap.isEmpty()) {
            logFailedAssertions();
            throw new WSSPolicyException(assertionMessage);
        }
    }

    private void logFailedAssertions() {
        Iterator<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMapIterator = this.failedAssertionStateMap.iterator();
        while (assertionStateMapIterator.hasNext()) {
            Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> map = assertionStateMapIterator.next();
            Set<Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> entrySet = map.entrySet();
            Iterator<Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> entryIterator = entrySet.iterator();
            while (entryIterator.hasNext()) {
                Map.Entry<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>> eventCollectionEntry = entryIterator.next();
                Map<Assertion, List<Assertable>> assertionListMap = eventCollectionEntry.getValue();
                Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateEntryIterator = assertionListMap.entrySet().iterator();
                while (assertionStateEntryIterator.hasNext()) {
                    Map.Entry<Assertion, List<Assertable>> entry = assertionStateEntryIterator.next();
                    List<Assertable> assertionStates = entry.getValue();
                    Iterator<Assertable> assertableIterator = assertionStates.iterator();
                    while (assertableIterator.hasNext()) {
                        Assertable assertable = assertableIterator.next();
                        if (!assertable.isAsserted() && !assertable.isLogged()) {
                            log.error(entry.getKey().getName() + " not satisfied: " + assertable.getErrorMessage());
                            assertable.setLogged(true);
                        }
                    }
                }
            }
        }
    }

    //multiple threads can call this method concurrently -> synchronize access
    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {

        if (operationSecurityEventOccured) {
            try {
                verifyPolicy(securityEvent);
            } catch (WSSPolicyException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
        }

        if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
            operationSecurityEventOccured = true;
            final OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
            if (effectivePolicy != null) {
                //soap-action spoofing detection
                if (!effectivePolicy.getOperationName().equals(operationSecurityEvent.getOperation().getLocalPart())) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, new WSSPolicyException("SOAPAction (" + effectivePolicy.getOperationName() + ") does not match with the current Operation: " + operationSecurityEvent.getOperation()));
                }
            } else {
                effectivePolicy = findPolicyBySOAPOperationName(operationPolicies, operationSecurityEvent.getOperation().getLocalPart());
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
            }
            try {
                Iterator<SecurityEvent> securityEventIterator = securityEventQueue.descendingIterator();
                while (securityEventIterator.hasNext()) {
                    SecurityEvent prevSecurityEvent = securityEventIterator.next();
                    verifyPolicy(prevSecurityEvent);
                }

                verifyPolicy(securityEvent);

                verifyPolicyAfterOperationSecurityEvent();
            } catch (WSSPolicyException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            securityEventQueue.clear();

            return;
        } else {
            securityEventQueue.push(securityEvent);
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
}
