/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ws.secpolicy11.builders;

import java.util.Iterator;
import java.util.List;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AlgorithmSuite;

import javax.xml.namespace.QName;

public class AlgorithmSuiteBuilder implements AssertionBuilder<OMElement> {
        
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        
        AlgorithmSuite algorithmSuite = new AlgorithmSuite(SPConstants.SP_V11);
        
        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);
                 
        Iterator iterAlterns = policy.getAlternatives();
        List assertions = ((List) iterAlterns.next());
        
        processAlternative(assertions, algorithmSuite);
                
        return algorithmSuite;
        
    }
    
    private void processAlternative(List assertions, AlgorithmSuite algorithmSuite) {        
        Iterator iterator = assertions.iterator();
        Assertion assertion = ((Assertion) iterator.next());
        String name = assertion.getName().getLocalPart();
        try {
            algorithmSuite.setAlgorithmSuite(name);
        } catch (WSSPolicyException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
    public QName[] getKnownElements() {
        return new QName[] {SP11Constants.ALGORITHM_SUITE};
    }
}
