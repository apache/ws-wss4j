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
import org.apache.neethi.builders.PrimitiveAssertion;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.*;
import org.swssf.policy.assertionStates.*;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.*;
import org.swssf.xmlsec.ext.SecurityToken;

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
    // Token Protection
    // finishing Layout
    // HttpsToken Algorithms
    //ProtectionOrder
    //Derived Keys property

    protected static final transient Log log = LogFactory.getLog(PolicyEnforcer.class);

    private List<OperationPolicy> operationPolicies;
    private OperationPolicy effectivePolicy;
    private List<Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> assertionStateMap;
    //securityEventQueue can probably be eliminated if we queue the events in the streaming-ws-security framework and
    //the first emitted event will be the operation event!
    private Deque<SecurityEvent> securityEventQueue = new LinkedList<SecurityEvent>();
    private boolean transportSecurityActive = false;
    private boolean operationSecurityEventOccured = false;

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
            assertableList = new ArrayList<Assertable>();
            assertables.put(keyAssertion, assertableList);
        }
        assertableList.add(assertable);
    }

    protected List<Assertable> getAssertableForAssertion(AbstractSecurityAssertion abstractSecurityAssertion) throws WSSPolicyException {
        List<Assertable> assertableList = new ArrayList<Assertable>();
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
        } else if (abstractSecurityAssertion instanceof AsymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof SymmetricBinding) {
        } else if (abstractSecurityAssertion instanceof TransportBinding) {
        } else if (abstractSecurityAssertion instanceof Layout) {
            assertableList.add(new LayoutAssertionState(abstractSecurityAssertion, true));
        }

        if (abstractSecurityAssertion instanceof AbstractBinding) {
            AbstractBinding abstractBinding = (AbstractBinding) abstractSecurityAssertion;
            if (abstractBinding instanceof AbstractSymmetricAsymmetricBinding) {
                AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) abstractSecurityAssertion;
                //todo:
                //assertableList.add(new ProtectionOrderAssertionState(abstractSymmetricAsymmetricBinding, false));
                assertableList.add(new SignatureProtectionAssertionState(abstractSymmetricAsymmetricBinding, true));
                assertableList.add(new OnlySignEntireHeadersAndBodyAssertionState(abstractSecurityAssertion, false));
                //todo token protection
            } else if (abstractSecurityAssertion instanceof TransportBinding) {
                if (abstractBinding.isIncludeTimestamp()) {
                    RequiredElementsAssertionState requiredElementsAssertionState = new RequiredElementsAssertionState(abstractBinding, false);
                    requiredElementsAssertionState.addElement(WSSConstants.TAG_wsu_Timestamp);
                    assertableList.add(requiredElementsAssertionState);
                }
            }

            assertableList.add(new IncludeTimeStampAssertionState(abstractBinding, true));
            if (abstractBinding.isIncludeTimestamp()) {
                SignedElementsAssertionState signedElementsAssertionState = new SignedElementsAssertionState(abstractSecurityAssertion, true);
                signedElementsAssertionState.addElement(WSSConstants.TAG_wsu_Timestamp);
                assertableList.add(signedElementsAssertionState);
            }
        } else if (abstractSecurityAssertion instanceof AbstractToken) {
            AbstractToken abstractToken = (AbstractToken) abstractSecurityAssertion;
            AbstractSecurityAssertion parentAssertion = abstractToken.getParentAssertion();
            if (parentAssertion instanceof SupportingTokens) {
                SupportingTokens supportingTokens = (SupportingTokens) parentAssertion;
                SupportingTokenType supportingTokenType = supportingTokens.getSupportingTokenType();
                if (supportingTokenType.getName().getLocalPart().startsWith("Signed")) {
                    SignedElementsAssertionState signedElementsAssertionState = new SignedElementsAssertionState(abstractSecurityAssertion, true);
                    assertableList.add(signedElementsAssertionState);
                    //todo the other tokens?
                    if (abstractToken instanceof UsernameToken) {
                        signedElementsAssertionState.addElement(WSSConstants.TAG_wsse_UsernameToken);
                    }
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
    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException {
        int notAssertedCount = 0;
        alternative:
        for (int i = 0; i < assertionStateMap.size(); i++) {
            Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(i);

            //every list entry counts as an alternative...
            Map<Assertion, List<Assertable>> assertionListMap = map.get(securityEvent.getSecurityEventType());
            if (assertionListMap != null && assertionListMap.size() > 0) {

                for (Iterator<Map.Entry<Assertion, List<Assertable>>> assertionStateIterator = assertionListMap.entrySet().iterator(); assertionStateIterator.hasNext(); ) {
                    Map.Entry<Assertion, List<Assertable>> assertionStateEntry = assertionStateIterator.next();
                    List<Assertable> assertionStates = assertionStateEntry.getValue();
                    for (int j = 0; j < assertionStates.size(); j++) {
                        Assertable assertable = assertionStates.get(j);
                        boolean asserted = assertable.assertEvent(securityEvent);
                        //...so if one fails, continue with the next map entry and increment the notAssertedCount
                        if (!asserted) {
                            notAssertedCount++;
                            continue alternative;
                        }
                    }
                }
            }
        }
        //if the notAssertedCount equals the size of the list (the size of the list is equal to the alternatives)
        //then we could not satisfy any alternative
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
        alternative:
        for (int i = 0; i < assertionStateMap.size(); i++) {
            Map<SecurityEvent.Event, Map<Assertion, List<Assertable>>> map = assertionStateMap.get(i);
            Iterator<Map.Entry<SecurityEvent.Event, Map<Assertion, List<Assertable>>>> iterator = map.entrySet().iterator();
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

        if (securityEvent instanceof HttpsTokenSecurityEvent) {
            transportSecurityActive = true;
        }

        if (operationSecurityEventOccured) {
            try {
                verifyPolicy(securityEvent);
            } catch (WSSPolicyException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
        }

        if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
            operationSecurityEventOccured = true;
            if (effectivePolicy != null) {
                //soap-action spoofing detection
                if (!effectivePolicy.getOperationName().equals(((OperationSecurityEvent) securityEvent).getOperation().getLocalPart())) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, new WSSPolicyException("SOAPAction (" + effectivePolicy.getOperationName() + ") does not match with the current Operation: " + ((OperationSecurityEvent) securityEvent).getOperation()));
                }
            } else {
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
            }

            try {
                identifySecurityTokenDepenedenciesAndUsage(securityEventQueue);
            } catch (PolicyViolationException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }

            Iterator<SecurityEvent> securityEventIterator = securityEventQueue.descendingIterator();
            while (securityEventIterator.hasNext()) {
                SecurityEvent prevSecurityEvent = securityEventIterator.next();
                try {
                    verifyPolicy(prevSecurityEvent);
                } catch (WSSPolicyException e) {
                    //todo better exceptions
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
            }
            securityEventQueue.clear();
        } else {
            //queue events until the operation security event occured
            securityEventQueue.push(securityEvent);
        }
    }

    private void identifySecurityTokenDepenedenciesAndUsage(Deque<SecurityEvent> securityEventDeque) throws PolicyViolationException, WSSecurityException {

        List<TokenSecurityEvent> messageSignatureTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> messageEncryptionTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> supportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> signedSupportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> endorsingSupportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> signedEndorsingSupportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> signedEncryptedSupportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> endorsingEncryptedSupportingTokens = new ArrayList<TokenSecurityEvent>();
        List<TokenSecurityEvent> signedEndorsingEncryptedSupportingTokens = new ArrayList<TokenSecurityEvent>();

        List<TokenSecurityEvent> tokenSecurityEvents = new LinkedList<TokenSecurityEvent>();
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            //todo it is probably better to use the EventType Enum instead of InstanceOf?
            if (securityEvent instanceof TokenSecurityEvent) {
                //iterator.remove();
                if (securityEvent instanceof HttpsTokenSecurityEvent) {
                    HttpsTokenSecurityEvent httpsTokenSecurityEvent = (HttpsTokenSecurityEvent) securityEvent;
                    httpsTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.MainSignature);
                    messageSignatureTokens.add(httpsTokenSecurityEvent);
                    HttpsTokenSecurityEvent clonedHttpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
                    clonedHttpsTokenSecurityEvent.setAuthenticationType(httpsTokenSecurityEvent.getAuthenticationType());
                    clonedHttpsTokenSecurityEvent.setIssuerName(httpsTokenSecurityEvent.getIssuerName());
                    clonedHttpsTokenSecurityEvent.setSecurityToken(httpsTokenSecurityEvent.getSecurityToken());
                    clonedHttpsTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.MainEncryption);
                    messageEncryptionTokens.add(clonedHttpsTokenSecurityEvent);
                    continue;
                }
                tokenSecurityEvents.add((TokenSecurityEvent) securityEvent);
            }
        }

        Iterator<TokenSecurityEvent> tokenSecurityEventIterator = tokenSecurityEvents.iterator();
        while (tokenSecurityEventIterator.hasNext()) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEventIterator.next();
            if (tokenSecurityEvent.getSecurityToken().getKeyWrappingToken() == null) {
                supportingTokens.add(tokenSecurityEvent);
            } else if (tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Encryption) {
                SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
                while (securityToken.getKeyWrappingToken() != null) {
                    securityToken = securityToken.getKeyWrappingToken();
                }
                TokenSecurityEvent encTokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
                encTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
                //todo handle multiple encryption tokens
                messageEncryptionTokens.add(encTokenSecurityEvent);
                securityEventDeque.offer(encTokenSecurityEvent);
            }
        }

        Iterator<TokenSecurityEvent> supportingTokensIterator = supportingTokens.iterator();
        while (supportingTokensIterator.hasNext()) {
            TokenSecurityEvent tokenSecurityEvent = supportingTokensIterator.next();
            List<SecurityToken> signingSecurityTokens = isSignedToken(tokenSecurityEvent, securityEventDeque);
            boolean signsSignature = signsElement(tokenSecurityEvent, WSSConstants.TAG_dsig_Signature, securityEventDeque);
            boolean signsSignatureConfirmation = signsElement(tokenSecurityEvent, WSSConstants.TAG_wsse11_SignatureConfirmation, securityEventDeque);
            boolean signsTimestamp = signsElement(tokenSecurityEvent, WSSConstants.TAG_wsu_Timestamp, securityEventDeque);
            if (!this.transportSecurityActive && signsSignatureConfirmation && signsTimestamp) {
                supportingTokensIterator.remove();
                messageSignatureTokens.add(tokenSecurityEvent);
            } else if (!this.transportSecurityActive && signsSignatureConfirmation) {
                supportingTokensIterator.remove();
                messageSignatureTokens.add(tokenSecurityEvent);
            } else if (!this.transportSecurityActive && signsTimestamp) {
                supportingTokensIterator.remove();
                messageSignatureTokens.add(tokenSecurityEvent);
            } else if (signsSignature && signingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedEndorsingSupportingTokens.add(tokenSecurityEvent);
            } else if (signsSignature) {
                supportingTokensIterator.remove();
                endorsingSupportingTokens.add(tokenSecurityEvent);
            } else if (signingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedSupportingTokens.add(tokenSecurityEvent);
            }
        }

        if (messageSignatureTokens.size() == 0) {
            SecurityToken messageSignatureToken = getSupportingTokenSigningToken(
                    signedSupportingTokens,
                    signedEndorsingSupportingTokens,
                    signedEncryptedSupportingTokens,
                    signedEndorsingEncryptedSupportingTokens,
                    securityEventDeque);

            TokenSecurityEvent tokenSecurityEvent = getTokenSecurityEvent(messageSignatureToken, tokenSecurityEvents);
            if (tokenSecurityEvent != null) {
                supportingTokens.remove(tokenSecurityEvent);
                signedSupportingTokens.remove(tokenSecurityEvent);
                endorsingSupportingTokens.remove(tokenSecurityEvent);
                signedEndorsingSupportingTokens.remove(tokenSecurityEvent);
                signedEncryptedSupportingTokens.remove(tokenSecurityEvent);
                endorsingEncryptedSupportingTokens.remove(tokenSecurityEvent);
                signedEndorsingEncryptedSupportingTokens.remove(tokenSecurityEvent);
                messageSignatureTokens.add(tokenSecurityEvent);
            }
        }

        if (messageSignatureTokens.size() == 0) {
            for (Iterator<TokenSecurityEvent> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent supportingToken = iterator.next();
                if (supportingToken.getTokenUsage() == TokenSecurityEvent.TokenUsage.Signature) {
                    iterator.remove();
                    messageSignatureTokens.add(supportingToken);
                    break;
                }
            }
        }

        if (messageEncryptionTokens.size() == 0) {
            for (Iterator<TokenSecurityEvent> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent supportingToken = iterator.next();
                if (supportingToken.getTokenUsage() == TokenSecurityEvent.TokenUsage.Encryption) {
                    iterator.remove();
                    messageEncryptionTokens.add(supportingToken);
                    break;
                }
            }
        }

        setTokenUsage(messageSignatureTokens, TokenSecurityEvent.TokenUsage.MainSignature);
        setTokenUsage(messageEncryptionTokens, TokenSecurityEvent.TokenUsage.MainEncryption);
        setTokenUsage(supportingTokens, TokenSecurityEvent.TokenUsage.SupportingToken);
        setTokenUsage(signedSupportingTokens, TokenSecurityEvent.TokenUsage.SignedSupportingTokens);
        setTokenUsage(endorsingSupportingTokens, TokenSecurityEvent.TokenUsage.EndorsingSupportingTokens);
        setTokenUsage(signedEndorsingSupportingTokens, TokenSecurityEvent.TokenUsage.SignedEndorsingSupportingTokens);
        setTokenUsage(signedEncryptedSupportingTokens, TokenSecurityEvent.TokenUsage.SignedEncryptedSupportingTokens);
        setTokenUsage(endorsingEncryptedSupportingTokens, TokenSecurityEvent.TokenUsage.EndorsingEncryptedSupportingTokens);
        setTokenUsage(signedEndorsingEncryptedSupportingTokens, TokenSecurityEvent.TokenUsage.SignedEndorsingEncryptedSupportingTokens);
    }

    private TokenSecurityEvent getTokenSecurityEvent(SecurityToken securityToken, List<TokenSecurityEvent> tokenSecurityEvents) {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            if (tokenSecurityEvent.getSecurityToken() == securityToken) {
                return tokenSecurityEvent;
            }
        }
        return null;
    }

    private SecurityToken getSupportingTokenSigningToken(
            List<TokenSecurityEvent> signedSupportingTokens,
            List<TokenSecurityEvent> signedEndorsingSupportingTokens,
            List<TokenSecurityEvent> signedEncryptedSupportingTokens,
            List<TokenSecurityEvent> signedEndorsingEncryptedSupportingTokens,
            Deque<SecurityEvent> securityEventDeque
    ) {

        //todo we have to check if the signingTokens also cover the other supporting tokens!
        for (int i = 0; i < signedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEndorsingSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEncryptedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEndorsingEncryptedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        return null;
    }

    private List<SecurityToken> getSigningToken(TokenSecurityEvent tokenSecurityEvent, Deque<SecurityEvent> securityEventDeque) {
        QName elementName = null;
        //todo element name in security Token?
        //todo the element name equality must be checked more precisely (inkl. path)!
        switch (tokenSecurityEvent.getSecurityEventType()) {
            case UsernameToken:
                elementName = WSSConstants.TAG_wsse_UsernameToken;
                break;
            case X509Token:
                //todo not always correct:
                elementName = WSSConstants.TAG_wsse_BinarySecurityToken;
                break;
        }
        if (elementName == null) {
            throw new RuntimeException("todo other token types...");
        }

        List<SecurityToken> signingSecurityTokens = new ArrayList<SecurityToken>();

        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent instanceof SignedElementSecurityEvent) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && signedElementSecurityEvent.getElement().equals(elementName)) {
                    signingSecurityTokens.add(signedElementSecurityEvent.getSecurityToken());
                }
            }
        }
        return signingSecurityTokens;
    }

    //todo overall linked-list and iterate with an iterator
    private void setTokenUsage(List<TokenSecurityEvent> tokenSecurityEvents, TokenSecurityEvent.TokenUsage tokenUsage) {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            tokenSecurityEvent.setTokenUsage(tokenUsage);
        }
    }

    private List<SecurityToken> isSignedToken(TokenSecurityEvent tokenSecurityEvent, Deque<SecurityEvent> securityEventDeque) {
        List<SecurityToken> securityTokenList = new ArrayList<SecurityToken>();
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            //todo it is probably better to use the EventType Enum instead of InstanceOf?
            if (securityEvent instanceof SignedElementSecurityEvent) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                //todo the element name equality must be checked more precisely (inkl. path)!
                if (signedElementSecurityEvent.isSigned()
                        //todo element name in security Tokem?
                        && tokenSecurityEvent instanceof UsernameTokenSecurityEvent
                        && WSSConstants.TAG_wsse_UsernameToken.equals(signedElementSecurityEvent.getElement())) {

                    if (!securityTokenList.contains(signedElementSecurityEvent.getSecurityToken())) {
                        securityTokenList.add(signedElementSecurityEvent.getSecurityToken());
                    }
                }
            }
        }
        return securityTokenList;
    }

    private List<SecurityToken> getElementSigningToken(QName element, Deque<SecurityEvent> securityEventDeque) {
        List<SecurityToken> securityTokenList = new ArrayList<SecurityToken>();
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            //todo it is probably better to use the EventType Enum instead of InstanceOf?
            if (securityEvent instanceof SignedElementSecurityEvent) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                //todo the element name equality must be checked more precisely (inkl. path)!
                if (signedElementSecurityEvent.isSigned()
                        && element.equals(signedElementSecurityEvent.getElement())) {
                    if (!securityTokenList.contains(signedElementSecurityEvent.getSecurityToken())) {
                        securityTokenList.add(signedElementSecurityEvent.getSecurityToken());
                    }
                }
            }
        }
        return securityTokenList;
    }

    private boolean signsElement(TokenSecurityEvent tokenSecurityEvent, QName element, Deque<SecurityEvent> securityEventDeque) {
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            //todo it is probably better to use the EventType Enum instead of InstanceOf?
            if (securityEvent instanceof SignedElementSecurityEvent) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                //todo the element name equality must be checked more precisely (inkl. path)!
                if (signedElementSecurityEvent.isSigned()
                        && signedElementSecurityEvent.getSecurityToken() == tokenSecurityEvent.getSecurityToken()
                        && element.equals(signedElementSecurityEvent.getElement())) {
                    return true;
                }
            }
        }
        return false;
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
