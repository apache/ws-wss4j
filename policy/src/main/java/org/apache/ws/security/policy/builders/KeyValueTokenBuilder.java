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
package org.apache.ws.security.policy.builders;

import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.security.policy.SP13Constants;
import org.apache.ws.security.policy.SPConstants;
import org.apache.ws.security.policy.SPUtils;
import org.apache.ws.security.policy.model.KeyValueToken;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class KeyValueTokenBuilder implements AssertionBuilder<Element> {

    public Assertion build(Element element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        final SPConstants.SPVersion spVersion = SPConstants.SPVersion.getSPVersion(element.getNamespaceURI());
        final String includeTokenValue = SPUtils.getAttribute(element, spVersion.getSPConstants().getIncludeToken());
        final Element issuer = SPUtils.getFirstChildElement(element, spVersion.getSPConstants().getIssuer());
        if (issuer != null) {
            throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
        }
        final String issuerName = SPUtils.getFirstChildElementText(element, spVersion.getSPConstants().getIssuerName());
        if (issuerName != null) {
            throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
        }
        final Element nestedPolicyElement = SPUtils.getFirstPolicyChildElement(element);
        if (nestedPolicyElement == null) {
            throw new IllegalArgumentException("sp:KeyValueToken must have an inner wsp:Policy element");
        }
        final Policy nestedPolicy = factory.getPolicyEngine().getPolicy(nestedPolicyElement);
        KeyValueToken keyValueToken = new KeyValueToken(
                spVersion,
                spVersion.getSPConstants().getInclusionFromAttributeValue(includeTokenValue),
                nestedPolicy
        );
        keyValueToken.setOptional(SPUtils.isOptional(element));
        keyValueToken.setIgnorable(SPUtils.isIgnorable(element));
        return keyValueToken;
    }

    public QName[] getKnownElements() {
        return new QName[]{SP13Constants.KEY_VALUE_TOKEN};
    }
}
