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
package org.apache.ws.security.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.ws.security.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class Trust10 extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    private Policy nestedPolicy;
    private boolean mustSupportClientChallenge;
    private boolean mustSupportServerChallenge;
    private boolean requireClientEntropy;
    private boolean requireServerEntropy;
    private boolean mustSupportIssuedTokens;

    public Trust10(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;

        parseNestedTrust10Policy(nestedPolicy, this);
    }

    public Policy getPolicy() {
        return nestedPolicy;
    }

    public QName getName() {
        return getVersion().getSPConstants().getTrust10();
    }

    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new Trust10(getVersion(), nestedPolicy);
    }

    protected void parseNestedTrust10Policy(Policy nestedPolicy, Trust10 trust10) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                if (getVersion().getSPConstants().getMustSupportClientChallenge().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustSupportClientChallenge().getNamespaceURI().equals(assertionNamespace)) {
                    if (trust10.isMustSupportClientChallenge()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    trust10.setMustSupportClientChallenge(true);
                    continue;
                }
                if (getVersion().getSPConstants().getMustSupportServerChallenge().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustSupportServerChallenge().getNamespaceURI().equals(assertionNamespace)) {
                    if (trust10.isMustSupportServerChallenge()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    trust10.setMustSupportServerChallenge(true);
                    continue;
                }
                if (getVersion().getSPConstants().getRequireClientEntropy().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireClientEntropy().getNamespaceURI().equals(assertionNamespace)) {
                    if (trust10.isRequireClientEntropy()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    trust10.setRequireClientEntropy(true);
                    continue;
                }
                if (getVersion().getSPConstants().getRequireServerEntropy().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireServerEntropy().getNamespaceURI().equals(assertionNamespace)) {
                    if (trust10.isRequireServerEntropy()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    trust10.setRequireServerEntropy(true);
                    continue;
                }
                if (getVersion().getSPConstants().getMustSupportIssuedTokens().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustSupportIssuedTokens().getNamespaceURI().equals(assertionNamespace)) {
                    if (trust10.isMustSupportIssuedTokens()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    trust10.setMustSupportIssuedTokens(true);
                    continue;
                }
            }
        }
    }

    public boolean isMustSupportClientChallenge() {
        return mustSupportClientChallenge;
    }

    protected void setMustSupportClientChallenge(boolean mustSupportClientChallenge) {
        this.mustSupportClientChallenge = mustSupportClientChallenge;
    }

    public boolean isMustSupportServerChallenge() {
        return mustSupportServerChallenge;
    }

    protected void setMustSupportServerChallenge(boolean mustSupportServerChallenge) {
        this.mustSupportServerChallenge = mustSupportServerChallenge;
    }

    public boolean isRequireClientEntropy() {
        return requireClientEntropy;
    }

    protected void setRequireClientEntropy(boolean requireClientEntropy) {
        this.requireClientEntropy = requireClientEntropy;
    }

    public boolean isRequireServerEntropy() {
        return requireServerEntropy;
    }

    protected void setRequireServerEntropy(boolean requireServerEntropy) {
        this.requireServerEntropy = requireServerEntropy;
    }

    public boolean isMustSupportIssuedTokens() {
        return mustSupportIssuedTokens;
    }

    protected void setMustSupportIssuedTokens(boolean mustSupportIssuedTokens) {
        this.mustSupportIssuedTokens = mustSupportIssuedTokens;
    }
}
