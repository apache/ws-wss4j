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
package org.apache.wss4j.policy.stax;

import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.neethi.Assertion;
import org.apache.neethi.ExactlyOne;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.neethi.PolicyOperator;
import org.apache.neethi.builders.PrimitiveAssertion;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.SPConstants.IncludeTokenType;
import org.apache.wss4j.policy.model.AbstractBinding;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.AlgorithmSuite;
import org.apache.wss4j.policy.model.ContentEncryptedElements;
import org.apache.wss4j.policy.model.EncryptedElements;
import org.apache.wss4j.policy.model.EncryptedParts;
import org.apache.wss4j.policy.model.HttpsToken;
import org.apache.wss4j.policy.model.IssuedToken;
import org.apache.wss4j.policy.model.KerberosToken;
import org.apache.wss4j.policy.model.KeyValueToken;
import org.apache.wss4j.policy.model.RelToken;
import org.apache.wss4j.policy.model.RequiredElements;
import org.apache.wss4j.policy.model.RequiredParts;
import org.apache.wss4j.policy.model.SamlToken;
import org.apache.wss4j.policy.model.SecureConversationToken;
import org.apache.wss4j.policy.model.SecurityContextToken;
import org.apache.wss4j.policy.model.SignedElements;
import org.apache.wss4j.policy.model.SignedParts;
import org.apache.wss4j.policy.model.SpnegoContextToken;
import org.apache.wss4j.policy.model.SupportingTokens;
import org.apache.wss4j.policy.model.UsernameToken;
import org.apache.wss4j.policy.model.X509Token;
import org.apache.wss4j.policy.model.Wss11;
import org.apache.wss4j.policy.stax.assertionStates.AlgorithmSuiteAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.ContentEncryptedElementsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.EncryptedElementsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.EncryptedPartsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.HttpsTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.IncludeTimeStampAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.IssuedTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.KerberosTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.KeyValueTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.OnlySignEntireHeadersAndBodyAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.ProtectionOrderAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.RelTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.RequiredElementsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.RequiredPartsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SamlTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SecureConversationTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SecurityContextTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SignatureConfirmationAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SignatureProtectionAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SignedElementsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SignedPartsAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.SpnegoContextTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.TokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.TokenProtectionAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.UsernameTokenAssertionState;
import org.apache.wss4j.policy.stax.assertionStates.X509TokenAssertionState;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

/**
 * The PolicyEnforcer verifies the Policy assertions
 * The Assertion will be validated in realtime as far as possible
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

    protected static final transient org.slf4j.Logger log = 
        org.slf4j.LoggerFactory.getLogger(PolicyEnforcer.class);

    private final List<OperationPolicy> operationPolicies;
    private OperationPolicy effectivePolicy;
    private final List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> assertionStateMap;
    private final List<Map<SecurityEventConstants.Event, Map<Assertion, List<Assertable>>>> failedAssertionStateMap;

    private final Deque<SecurityEvent> securityEventQueue = new LinkedList<SecurityEvent>();
    private boolean operationSecurityEventOccured = false;
    private boolean initiator;
    private String actorOrRole;
    private int attachmentCount;

    public PolicyEnforcer(List<OperationPolicy> operationPolicies, String soapAction, boolean initiator,
                          String actorOrRole, int attachmentCount) throws WSSPolicyException {
        this.operationPolicies = operationPolicies;
        this.initiator = initiator;
        this.actorOrRole = actorOrRole;
        this.attachmentCount = attachmentCount;
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
        } else if (!(policyComponent instanceof PrimitiveAssertion)) {
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
        if (abstractSecurityAssertion instanceof AbstractToken) {
            // Don't return a Token that is not required
            SPConstants.IncludeTokenType includeTokenType = 
                ((AbstractToken)abstractSecurityAssertion).getIncludeTokenType();
            if (includeTokenType == IncludeTokenType.INCLUDE_TOKEN_NEVER) {
                return assertableList;
            } else if (initiator && includeTokenType == IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_RECIPIENT) {
                return assertableList;
            } else if (initiator && includeTokenType == IncludeTokenType.INCLUDE_TOKEN_ONCE) {
                return assertableList;
            } else if (!initiator && includeTokenType == IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_INITIATOR) {
                return assertableList;
            }
        }
        
        if (abstractSecurityAssertion instanceof ContentEncryptedElements) {
            //initialized with asserted=true because it could be that parent elements are encrypted and therefore these element are also encrypted
            //the test if it is really encrypted is done via the PolicyInputProcessor which emits EncryptedElementEvents for unencrypted elements with the unencrypted flag
            assertableList.add(new ContentEncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof EncryptedParts) {
            //initialized with asserted=true with the same reason as by the EncryptedParts above
            assertableList.add(new EncryptedPartsAssertionState(abstractSecurityAssertion, true, attachmentCount));
        } else if (abstractSecurityAssertion instanceof EncryptedElements) {
            //initialized with asserted=true with the same reason as by the EncryptedParts above
            assertableList.add(new EncryptedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof SignedParts) {
            //initialized with asserted=true because it could be that parent elements are signed and therefore these element are also signed
            //the test if it is really signed is done via the PolicyInputProcessor which emits SignedElementEvents for unsigned elements with the unsigned flag
            assertableList.add(new SignedPartsAssertionState(abstractSecurityAssertion, true, attachmentCount));
        } else if (abstractSecurityAssertion instanceof SignedElements) {
            //initialized with asserted=true with the same reason as by the SignedParts above
            assertableList.add(new SignedElementsAssertionState(abstractSecurityAssertion, true));
        } else if (abstractSecurityAssertion instanceof RequiredElements) {
            assertableList.add(new RequiredElementsAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof RequiredParts) {
            assertableList.add(new RequiredPartsAssertionState(abstractSecurityAssertion, false));
        } else if (abstractSecurityAssertion instanceof UsernameToken) {
            assertableList.add(new UsernameTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof IssuedToken) {
            assertableList.add(new IssuedTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof X509Token) {
            assertableList.add(new X509TokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof KerberosToken) {
            assertableList.add(new KerberosTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof SpnegoContextToken) {
            assertableList.add(new SpnegoContextTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof SecureConversationToken) {
            assertableList.add(new SecureConversationTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof SecurityContextToken) {
            assertableList.add(new SecurityContextTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof SamlToken) {
            assertableList.add(new SamlTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof RelToken) {
            assertableList.add(new RelTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof HttpsToken && !initiator) {
            assertableList.add(new HttpsTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof KeyValueToken) {
            assertableList.add(new KeyValueTokenAssertionState(abstractSecurityAssertion, false, initiator));
        } else if (abstractSecurityAssertion instanceof AlgorithmSuite) {
            //initialized with asserted=true because we do negative matching
            assertableList.add(new AlgorithmSuiteAssertionState(abstractSecurityAssertion, true));
        } /*else if (abstractSecurityAssertion instanceof AsymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof SymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof TransportBinding) {
        } else if (abstractSecurityAssertion instanceof Layout) {
            assertableList.add(new LayoutAssertionState(abstractSecurityAssertion, true));
        }*/

        else if (abstractSecurityAssertion instanceof AbstractBinding) {
            AbstractBinding abstractBinding = (AbstractBinding) abstractSecurityAssertion;
            if (abstractBinding instanceof AbstractSymmetricAsymmetricBinding) {
                AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) abstractSecurityAssertion;
                assertableList.add(new ProtectionOrderAssertionState(abstractSymmetricAsymmetricBinding, true));
                assertableList.add(new SignatureProtectionAssertionState(abstractSymmetricAsymmetricBinding, true));
                if (abstractSymmetricAsymmetricBinding.isOnlySignEntireHeadersAndBody()) {
                    //initialized with asserted=true because we do negative matching
                    assertableList.add(new OnlySignEntireHeadersAndBodyAssertionState(abstractSecurityAssertion, true, actorOrRole));
                }
                assertableList.add(new TokenProtectionAssertionState(abstractSecurityAssertion, true));
            }

            //WSP1.3, 6.2 Timestamp Property
            assertableList.add(new IncludeTimeStampAssertionState(abstractBinding, true));
            if (abstractBinding.isIncludeTimestamp()) {
                List<QName> timestampElementPath = new LinkedList<QName>();
                timestampElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
                timestampElementPath.add(WSSConstants.TAG_wsu_Timestamp);
                RequiredElementsAssertionState requiredElementsAssertionState = new RequiredElementsAssertionState(abstractBinding, false);
                requiredElementsAssertionState.addElement(timestampElementPath);
                assertableList.add(requiredElementsAssertionState);

                SignedElementsAssertionState signedElementsAssertionState = new SignedElementsAssertionState(abstractSecurityAssertion, true);
                signedElementsAssertionState.addElement(timestampElementPath);
                assertableList.add(signedElementsAssertionState);
            }
        } else if (abstractSecurityAssertion instanceof Wss11) {
            Wss11 wss11 = (Wss11)abstractSecurityAssertion;

            if (initiator) {
                //9 WSS: SOAP Message Security Options [Signature Confirmation]
                assertableList.add(new SignatureConfirmationAssertionState(wss11, true));
                if (wss11.isRequireSignatureConfirmation()) {
                    List<QName> signatureConfirmationElementPath = new LinkedList<QName>();
                    signatureConfirmationElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
                    signatureConfirmationElementPath.add(WSSConstants.TAG_wsse11_SignatureConfirmation);
                    RequiredElementsAssertionState requiredElementsAssertionState = new RequiredElementsAssertionState(wss11, false);
                    requiredElementsAssertionState.addElement(signatureConfirmationElementPath);
                    assertableList.add(requiredElementsAssertionState);

                    SignedElementsAssertionState signedElementsAssertionState = new SignedElementsAssertionState(wss11, true);
                    signedElementsAssertionState.addElement(signatureConfirmationElementPath);
                    assertableList.add(signedElementsAssertionState);
                }
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
                            //Other tokens may not be resolved yet fully therefore we skip it here
                            if (assertion instanceof SupportingTokens ||
                                    assertable instanceof HttpsTokenAssertionState ||
                                    assertable instanceof RelTokenAssertionState ||
                                    assertable instanceof SecurityContextTokenAssertionState ||
                                    assertable instanceof SpnegoContextTokenAssertionState ||
                                    assertable instanceof UsernameTokenAssertionState) {
                                doAssert = true;
                            }
                        } else if (assertable instanceof TokenProtectionAssertionState ||
                                assertable instanceof SignatureConfirmationAssertionState ||
                                assertable instanceof IncludeTimeStampAssertionState ||
                                assertable instanceof RequiredPartsAssertionState ||
                                assertable instanceof SignatureProtectionAssertionState) {
                            doAssert = true;
                        }

                        if ((doAssert || assertable.isHardFailure()) && !assertable.isAsserted()) {
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
    @Override
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

        if (WSSecurityEventConstants.Operation.equals(securityEvent.getSecurityEventType())) {
            operationSecurityEventOccured = true;
            final OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
            if (effectivePolicy == null) {
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
