/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy.secpolicy;

import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyOperator;

import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyUtil {

    public static SPConstants getSPVersion(String namespace) {
        if (SP13Constants.SP_NS.equals(namespace)) {
            return SP13Constants.INSTANCE;
        } else if (SP12Constants.SP_NS.equals(namespace)) {
            return SP12Constants.INSTANCE;
        } else if (SP11Constants.SP_NS.equals(namespace)) {
            return SP11Constants.INSTANCE;
        }
        return null;
    }

    public static List<Assertion> getPolicyAssertionsInSameAlternative(PolicyComponent policy, Assertion policyAssertion, Class<? extends Assertion> policyAssertionToSearchFor, Object... initArgs) {
        List<Assertion> policyAssertions = new ArrayList<Assertion>();
        PolicyOperator foundPolicyOperator = (PolicyOperator) getPolicyAssertionParentOperator(policy, policyAssertion, null);
        getPolicyAssertion(policyAssertions, foundPolicyOperator, policyAssertionToSearchFor);
        if (policyAssertions.size() == 0) {
            //ok no matching Assertion found, so append one
            //atm we append it directly on the operator. this is probably not the correct place
            Class[] params = new Class[initArgs.length];
            for (int i = 0; i < initArgs.length; i++) {
                Object initArg = initArgs[i];
                //todo better solution:
                if (i == initArgs.length - 1) {
                    params[i] = initArg.getClass().getSuperclass();
                } else {
                    params[i] = initArg.getClass();
                }
            }
            try {
                Assertion assertion = policyAssertionToSearchFor.getConstructor(params).newInstance(initArgs);
                policyAssertions.add(assertion);
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        return policyAssertions;
    }

    public static PolicyComponent getPolicyAssertionParentOperator(PolicyComponent policy, Assertion policyAssertion, PolicyComponent parent) {
        if (policy instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policy;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent policyComponent = policyComponents.get(i);
                PolicyComponent foundPolicyComponent = getPolicyAssertionParentOperator(policyComponent, policyAssertion, policyOperator);
                if (foundPolicyComponent != null) {
                    return foundPolicyComponent;
                }
            }
        } else {
            Assertion foundPolicyAssertion = (Assertion) policy;
            if (foundPolicyAssertion == policyAssertion) {
                return parent;
            } else {
                return null;
            }
        }
        return null;
    }

    public static void getPolicyAssertion(List<Assertion> foundPolicies, PolicyComponent policyComponent, Class<? extends Assertion> policyAssertionClass) {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            @SuppressWarnings("unchecked")
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curpolicyComponent = policyComponents.get(i);
                getPolicyAssertion(foundPolicies, curpolicyComponent, policyAssertionClass);
            }
        } else {
            Assertion foundPolicyAssertion = (Assertion) policyComponent;
            if (foundPolicyAssertion.getClass() == policyAssertionClass) {
                foundPolicies.add(foundPolicyAssertion);
            }
        }
    }
}
