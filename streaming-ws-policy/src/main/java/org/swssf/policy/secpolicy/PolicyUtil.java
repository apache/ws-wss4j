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
