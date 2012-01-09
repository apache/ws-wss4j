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

package org.apache.ws.security;

import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.opensaml.common.SAMLVersion;

import java.io.Serializable;
import java.security.Principal;

/**
 * A principal that represents a SAML Token. It parses the Subject and returns the Subject 
 * name value as the Principal name.
 */
public class SAMLTokenPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 1L;
    
    private String name;
    private AssertionWrapper assertion;
    
    public SAMLTokenPrincipal(AssertionWrapper assertion) {
        this.assertion = assertion;
        if (assertion.getSamlVersion() == SAMLVersion.VERSION_20) {
            org.opensaml.saml2.core.Subject subject = assertion.getSaml2().getSubject();
            if (subject != null && subject.getNameID() != null) {
                name = subject.getNameID().getValue();
            }
        } else {
            org.opensaml.saml1.core.Subject samlSubject = null;
            for (org.opensaml.saml1.core.Statement stmt : assertion.getSaml1().getStatements()) {
                if (stmt instanceof org.opensaml.saml1.core.AttributeStatement) {
                    org.opensaml.saml1.core.AttributeStatement attrStmt = 
                        (org.opensaml.saml1.core.AttributeStatement) stmt;
                    samlSubject = attrStmt.getSubject();
                } else if (stmt instanceof org.opensaml.saml1.core.AuthenticationStatement) {
                    org.opensaml.saml1.core.AuthenticationStatement authStmt = 
                        (org.opensaml.saml1.core.AuthenticationStatement) stmt;
                    samlSubject = authStmt.getSubject();
                } else {
                    org.opensaml.saml1.core.AuthorizationDecisionStatement authzStmt =
                        (org.opensaml.saml1.core.AuthorizationDecisionStatement)stmt;
                    samlSubject = authzStmt.getSubject();
                }
                if (samlSubject != null) {
                    break;
                }
            }
            if (samlSubject != null && samlSubject.getNameIdentifier() != null) {
                name = samlSubject.getNameIdentifier().getNameIdentifier();
            }
        }
    }
    
    public AssertionWrapper getToken() {
        return assertion;
    }

    public String getName() {
        return this.name;
    }

    public String getId() {
        if (assertion != null) {
            return assertion.getId();
        }
        return null;
    }
    
}
