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
package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.AsymmetricBinding;
import org.apache.ws.secpolicy.model.InitiatorToken;
import org.apache.ws.secpolicy.model.Layout;
import org.apache.ws.secpolicy.model.RecipientToken;

public class AsymmetricBindingBuilder implements AssertionBuilder<OMElement> {

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        
        AsymmetricBinding asymmetricBinding =  new AsymmetricBinding(SPConstants.SP_V12);
        
        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);
        
        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative((List) iterator.next(), asymmetricBinding);
            
            /*
             * since there should be only one alternative
             */
            break;
        }
        
        return asymmetricBinding;
    }
    
    private void processAlternative(List assertions, AsymmetricBinding asymmetricBinding) {
               
        Assertion assertion;
        QName name;
        
        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();
            
            if (SP12Constants.INITIATOR_TOKEN.equals(name)) {
                asymmetricBinding.setInitiatorToken((InitiatorToken) assertion);
                
            } else if (SP12Constants.RECIPIENT_TOKEN.equals(name)){
                asymmetricBinding.setRecipientToken((RecipientToken) assertion);
                
            } else if (SP12Constants.ALGORITHM_SUITE.equals(name)) {
                asymmetricBinding.setAlgorithmSuite((AlgorithmSuite) assertion);
            
            } else if (SP12Constants.LAYOUT.equals(name)) {
                asymmetricBinding.setLayout((Layout) assertion);
                
            } else if (SP12Constants.INCLUDE_TIMESTAMP.equals(name)) {
                asymmetricBinding.setIncludeTimestamp(true);
                asymmetricBinding.setIncludeTimestampOptional(assertion.isOptional());

            } else if (SP12Constants.ENCRYPT_BEFORE_SIGNING.equals(name)) {
                asymmetricBinding.setProtectionOrder(SPConstants.ENCRYPT_BEFORE_SIGNING);
                
            } else if (SP12Constants.SIGN_BEFORE_ENCRYPTING.equals(name)) {
                asymmetricBinding.setProtectionOrder(SPConstants.SIGN_BEFORE_ENCRYPTING);
                
            } else if (SP12Constants.ENCRYPT_SIGNATURE.equals(name)) {
                asymmetricBinding.setSignatureProtection(true);
                
            } else if (SP12Constants.PROTECT_TOKENS.equals(name)) {
                asymmetricBinding.setTokenProtection(true);
                
            } else if (SPConstants.ONLY_SIGN_ENTIRE_HEADERS_AND_BODY
                    .equals(name.getLocalPart())) {
                asymmetricBinding.setEntireHeadersAndBodySignatures(true);
            }
        }
    }
    
    public QName[] getKnownElements() {
        return new QName[]{SP12Constants.ASYMMETRIC_BINDING};
    }
    
}
 