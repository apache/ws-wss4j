package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.ext.XMLSecurityException;
import ch.gigerstyle.xmlsec.policy.assertionStates.AssertionState;
import ch.gigerstyle.xmlsec.policy.secpolicy.WSSPolicyException;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.securityEvent.OperationSecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEventListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.ExactlyOne;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyOperator;

import java.util.*;

/**
 * User: giger
 * Date: Sep 2, 2010
 * Time: 8:07:59 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class PolicyEnforcer implements SecurityEventListener {
    //todo exceptions! don't leak informations!!
    protected static final transient Log log = LogFactory.getLog(PolicyEnforcer.class);

    private List<OperationPolicy> operationPolicies;
    private OperationPolicy effectivePolicy;
    private Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap;

    private ArrayDeque<SecurityEvent> securityEventQueue = new ArrayDeque<SecurityEvent>();

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

    private Map<SecurityEvent.Event, Collection<AssertionState>> initAssertionStateMap() {
        Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap = new HashMap<SecurityEvent.Event, Collection<AssertionState>>();

        for (SecurityEvent.Event securityEvent : SecurityEvent.Event.values()) {
            assertionStateMap.put(securityEvent, new ArrayList<AssertionState>());
        }

        return assertionStateMap;
    }

    private void buildAssertionStateMap(PolicyComponent policyComponent, Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                buildAssertionStateMap(curPolicyComponent, assertionStateMap);
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            abstractSecurityAssertion.getAssertions(assertionStateMap);
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }

    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException {

        Collection<AssertionState> assertionStates = assertionStateMap.get(securityEvent.getSecurityEventType());
        if (assertionStates != null && assertionStates.size() > 0) {
            int notAssertedCount = 0;
            for (Iterator<AssertionState> assertionStateIterator = assertionStates.iterator(); assertionStateIterator.hasNext();) {
                AssertionState assertionState = assertionStateIterator.next();
                boolean asserted = assertionState.assertEvent(securityEvent);
                if (!asserted) {
                    notAssertedCount++;
                }
            }
            //todo hmm this is not correct:
            //if you have e.g. an IncludeTimeStamp (which must be signed per policy-spec) and a signedElement assertion
            //and one of them is asserted, we will always return true. We have to do somehow an additional
            //check if some of the assertions in assertionStates belongs to the same alternative.
            //Sample: the following policy will always return true when one of them is fullfilled:
            //<sp:IncludeTimestamp/>
            //<sp:SignedElements>
            //<sp:XPath xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">wsu:Created</sp:XPath>
            //</sp:SignedElements>
            if (notAssertedCount == assertionStates.size()) {
                logFailedAssertions();
                throw new WSSPolicyException("No policy alternative could be satisfied");
            }
        }
    }

    private void verifyPolicy() throws WSSPolicyException, PolicyViolationException {
        boolean isAsserted = verifyPolicy(effectivePolicy.getPolicy());
        if (!isAsserted) {
            logFailedAssertions();
            throw new PolicyViolationException("No policy alternative could be satisfied");
        }
    }

    private boolean verifyPolicy(PolicyComponent policyComponent) throws WSSPolicyException, PolicyViolationException {

        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            boolean isExactlyOne = policyOperator instanceof ExactlyOne;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();

            boolean isAsserted = false;
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
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
        Set<Map.Entry<SecurityEvent.Event, Collection<AssertionState>>> entrySet = assertionStateMap.entrySet();
        Iterator<Map.Entry<SecurityEvent.Event, Collection<AssertionState>>> entryIterator = entrySet.iterator();
        while (entryIterator.hasNext()) {
            Map.Entry<SecurityEvent.Event, Collection<AssertionState>> eventCollectionEntry = entryIterator.next();
            Collection<AssertionState> assertionStates = eventCollectionEntry.getValue();
            for (Iterator<AssertionState> assertionStateIterator = assertionStates.iterator(); assertionStateIterator.hasNext();) {
                AssertionState assertionState = assertionStateIterator.next();
                log.error(assertionState.getErrorMessage());
            }
        }
    }

    //multiple threads can call this method concurrently -> synchronize access

    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {

        if (effectivePolicy != null) {
            //soap-action spoofing detection
            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                if (!effectivePolicy.getOperationName().equals(((OperationSecurityEvent) securityEvent).getOperation().getLocalPart())) {
                    throw new WSSPolicyException("SOAPAction does not match with the current Operation");
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
                    verifyPolicy(prevSecurityEvent);
                }

            } else {
                //queue event until policy is resolved
                securityEventQueue.push(securityEvent);
            }
        }
    }

    public void doFinal() throws PolicyViolationException {
        try {
            verifyPolicy();
        } catch (Exception e) {
            throw new PolicyViolationException(e);
        }
    }
}
