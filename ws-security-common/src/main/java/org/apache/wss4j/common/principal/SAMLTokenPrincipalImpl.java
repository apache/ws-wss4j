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

import org.apache.wss4j.common.saml.SamlAssertionWrapper;

import java.io.Serializable;

/**
 * A principal that represents a SAML Token. It parses the Subject and returns the Subject
 * name value as the Principal name.
 */
public class SAMLTokenPrincipalImpl implements Serializable, SAMLTokenPrincipal {
    private static final long serialVersionUID = 1L;

    private String name;
    private SamlAssertionWrapper samlAssertion;

    public SAMLTokenPrincipalImpl(SamlAssertionWrapper samlAssertion) {
        this.samlAssertion = samlAssertion;
        this.name = samlAssertion.getSubjectName();
    }

    @Override
    public SamlAssertionWrapper getToken() {
        return samlAssertion;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getId() {
        if (samlAssertion != null) {
            return samlAssertion.getId();
        }
        return null;
    }

}
