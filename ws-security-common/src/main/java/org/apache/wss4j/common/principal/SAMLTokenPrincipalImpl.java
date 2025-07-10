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

package org.apache.wss4j.common.principal;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * A principal that represents a SAML Token. It parses the Subject and returns the Subject
 * name value as the Principal name.
 */
public class SAMLTokenPrincipalImpl implements Serializable, SAMLTokenPrincipal {
    private static final long serialVersionUID = 1L;

    private String name;
    private Object samlAssertion;

    public SAMLTokenPrincipalImpl(Object samlAssertion) throws WSSecurityException {
        this.samlAssertion = samlAssertion;
        
        if (samlAssertion == null) {
            throw new IllegalArgumentException("SAML Assertion cannot be null");
        }

        // Use reflection to extract the subject name from the SAML assertion
        try {
            Class<?> samlAssertionWrapperClass = Class.forName("org.apache.wss4j.dom.saml.SamlAssertionWrapper");
            if (samlAssertionWrapperClass.isInstance(samlAssertion)) {
                Object samlWrapper = samlAssertionWrapperClass.cast(samlAssertion);
                this.name = (String) samlAssertionWrapperClass.getMethod("getSubjectName").invoke(samlWrapper);
            } else {
                throw new IllegalArgumentException("Provided SAML Assertion is not of the expected type");
            }
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity", 
                new Object[] {"Error extracting subject name from SAML Assertion"});
        }
    }

    @Override
    public Object getToken() {
        return samlAssertion;
    }

    @Override
    public String getName() {
        return this.name;
    }

}
