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
package org.apache.wss4j.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

public class Wss10 extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    private Policy nestedPolicy;
    private boolean mustSupportRefKeyIdentifier;
    private boolean mustSupportRefIssuerSerial;
    private boolean mustSupportRefExternalURI;
    private boolean mustSupportRefEmbeddedToken;

    public Wss10(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;

        parseNestedWss10Policy(nestedPolicy, this);
    }

    @Override
    public Policy getPolicy() {
        return this.nestedPolicy;
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getWss10();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof Wss10)) {
            return false;
        }

        Wss10 that = (Wss10)object;
        if (mustSupportRefKeyIdentifier != that.mustSupportRefKeyIdentifier
            || mustSupportRefIssuerSerial != that.mustSupportRefIssuerSerial
            || mustSupportRefExternalURI != that.mustSupportRefExternalURI
            || mustSupportRefEmbeddedToken != that.mustSupportRefEmbeddedToken) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + Boolean.hashCode(mustSupportRefKeyIdentifier);
        result = 31 * result + Boolean.hashCode(mustSupportRefIssuerSerial);
        result = 31 * result + Boolean.hashCode(mustSupportRefExternalURI);
        result = 31 * result + Boolean.hashCode(mustSupportRefEmbeddedToken);

        return 31 * result + super.hashCode();
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new Wss10(getVersion(), nestedPolicy);
    }

    protected void parseNestedWss10Policy(Policy nestedPolicy, Wss10 wss10) {
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

                QName mustSupportRefKeyIdentifier = getVersion().getSPConstants().getMustSupportRefKeyIdentifier();
                if (mustSupportRefKeyIdentifier.getLocalPart().equals(assertionName)
                    && mustSupportRefKeyIdentifier.getNamespaceURI().equals(assertionNamespace)) {
                    if (wss10.isMustSupportRefKeyIdentifier()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss10.setMustSupportRefKeyIdentifier(true);
                    continue;
                }

                QName mustSupportRefIssuerSerial = getVersion().getSPConstants().getMustSupportRefIssuerSerial();
                if (mustSupportRefIssuerSerial.getLocalPart().equals(assertionName)
                    && mustSupportRefIssuerSerial.getNamespaceURI().equals(assertionNamespace)) {
                    if (wss10.isMustSupportRefIssuerSerial()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss10.setMustSupportRefIssuerSerial(true);
                    continue;
                }

                QName mustSupportRefExternal = getVersion().getSPConstants().getMustSupportRefExternalUri();
                if (mustSupportRefExternal.getLocalPart().equals(assertionName)
                    && mustSupportRefExternal.getNamespaceURI().equals(assertionNamespace)) {
                    if (wss10.isMustSupportRefExternalURI()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss10.setMustSupportRefExternalURI(true);
                    continue;
                }

                QName mustSupportRefEmbedded = getVersion().getSPConstants().getMustSupportRefEmbeddedToken();
                if (mustSupportRefEmbedded.getLocalPart().equals(assertionName)
                    && mustSupportRefEmbedded.getNamespaceURI().equals(assertionNamespace)) {
                    if (wss10.isMustSupportRefEmbeddedToken()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss10.setMustSupportRefEmbeddedToken(true);
                    continue;
                }
            }
        }
    }

    public boolean isMustSupportRefKeyIdentifier() {
        return mustSupportRefKeyIdentifier;
    }

    protected void setMustSupportRefKeyIdentifier(boolean mustSupportRefKeyIdentifier) {
        this.mustSupportRefKeyIdentifier = mustSupportRefKeyIdentifier;
    }

    public boolean isMustSupportRefIssuerSerial() {
        return mustSupportRefIssuerSerial;
    }

    protected void setMustSupportRefIssuerSerial(boolean mustSupportRefIssuerSerial) {
        this.mustSupportRefIssuerSerial = mustSupportRefIssuerSerial;
    }

    public boolean isMustSupportRefExternalURI() {
        return mustSupportRefExternalURI;
    }

    protected void setMustSupportRefExternalURI(boolean mustSupportRefExternalURI) {
        this.mustSupportRefExternalURI = mustSupportRefExternalURI;
    }

    public boolean isMustSupportRefEmbeddedToken() {
        return mustSupportRefEmbeddedToken;
    }

    protected void setMustSupportRefEmbeddedToken(boolean mustSupportRefEmbeddedToken) {
        this.mustSupportRefEmbeddedToken = mustSupportRefEmbeddedToken;
    }
}
