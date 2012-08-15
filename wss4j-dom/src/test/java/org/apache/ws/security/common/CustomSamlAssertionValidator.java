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

package org.apache.ws.security.common;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.SamlAssertionValidator;

public class CustomSamlAssertionValidator extends SamlAssertionValidator {
    
    @Override
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        Credential returnedCredential = super.validate(credential, data);
        
        //
        // Do some custom validation on the assertion
        //
        AssertionWrapper assertion = credential.getAssertion();
        if (!"www.example.com".equals(assertion.getIssuerString())) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }
        if (assertion.getSaml1() != null) {
            // Get the SAML subject and validate it
            org.opensaml.saml1.core.Assertion saml1Assertion = assertion.getSaml1();
            org.opensaml.saml1.core.Subject samlSubject = null;
            for (org.opensaml.saml1.core.Statement stmt : saml1Assertion.getStatements()) {
                if (stmt instanceof org.opensaml.saml1.core.AttributeStatement) {
                    org.opensaml.saml1.core.AttributeStatement attrStmt = 
                        (org.opensaml.saml1.core.AttributeStatement) stmt;
                    samlSubject = attrStmt.getSubject();
                    break;
                } else if (stmt instanceof org.opensaml.saml1.core.AuthenticationStatement) {
                    org.opensaml.saml1.core.AuthenticationStatement authStmt = 
                        (org.opensaml.saml1.core.AuthenticationStatement) stmt;
                    samlSubject = authStmt.getSubject();
                    break;
                } else {
                    org.opensaml.saml1.core.AuthorizationDecisionStatement authzStmt =
                        (org.opensaml.saml1.core.AuthorizationDecisionStatement)stmt;
                    samlSubject = authzStmt.getSubject();
                }
            }
                
            if (samlSubject == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLToken", 
                    new Object[] {"for Signature (no Subject)"}
                );
            }
            String nameIdentifier = samlSubject.getNameIdentifier().getNameIdentifier();
            if (nameIdentifier == null || !nameIdentifier.contains("uid=joe")) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        } else {
            org.opensaml.saml2.core.Assertion saml2Assertion = assertion.getSaml2();
            org.opensaml.saml2.core.Subject subject = saml2Assertion.getSubject();
            String nameIdentifier = subject.getNameID().getValue();
            if (nameIdentifier == null || !nameIdentifier.contains("uid=joe")) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        }
        
        return returnedCredential;
    }
    
}