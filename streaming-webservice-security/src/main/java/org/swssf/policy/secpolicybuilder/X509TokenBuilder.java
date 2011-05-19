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
package org.swssf.policy.secpolicybuilder;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.X509Token;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class X509TokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.X509_TOKEN,
            SP12Constants.X509_TOKEN,
            SP13Constants.X509_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        X509Token x509Token = new X509Token(spConstants);

        OMElement issuer = element.getFirstChildWithName(spConstants.getIssuer());
        if (issuer != null) {
            x509Token.setIssuer(issuer.getText());
        }

        OMElement issuerName = element.getFirstChildWithName(spConstants.getIssuerName());
        if (issuerName != null) {
            x509Token.setIssuerName(issuerName.getText());
        }

        //Process token inclusion
        OMAttribute includeAttr = element.getAttribute(spConstants.getIncludeToken());
        if (includeAttr != null) {
            SPConstants.IncludeTokenType inclusion = spConstants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());
            x509Token.setInclusion(inclusion);
        }

        Policy policy = PolicyEngine.getPolicy(element.getFirstChildWithName(SPConstants.POLICY));
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator
                .hasNext(); ) {
            processAlternative((List) iterator.next(), x509Token, spConstants);

            /*
            * since there should be only one alternative
            */
            break;
        }

        return x509Token;
    }

    private void processAlternative(List assertions, X509Token parent, SPConstants spConstants) {
        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext(); ) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (spConstants.getRequiredDerivedKeys().equals(name)) {
                parent.setDerivedKeys(true);

            } else if (spConstants.getRequireImpliedDerivedKeys().equals(name)) {
                parent.setImpliedDerivedKeys(true);

            } else if (spConstants.getRequireExplicitDerivedKeys().equals(name)) {
                parent.setExplicitDerivedKeys(true);

            } else if (spConstants.getRequireKeyIdentifireReference().equals(name)) {
                parent.setRequireKeyIdentifierReference(true);

            } else if (spConstants.getRequireIssuerSerialReference().equals(name)) {
                parent.setRequireIssuerSerialReference(true);

            } else if (spConstants.getRequireEmbeddedTokenReference().equals(name)) {
                parent.setRequireEmbeddedTokenReference(true);

            } else if (spConstants.getRequireThumbprintReference().equals(name)) {
                parent.setRequireThumbprintReference(true);

            } else if (spConstants.getWssX509V1Token10().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_V1_TOKEN10);

            } else if (spConstants.getWssX509V1Token11().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_V1_TOKEN11);

            } else if (spConstants.getWssX509V3Token10().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_V3_TOKEN10);

            } else if (spConstants.getWssX509V3Token11().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_V3_TOKEN11);

            } else if (spConstants.getWssX509Pkcs7Token10().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_PKCS7_TOKEN10);

            } else if (spConstants.getWssX509Pkcs7Token11().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_PKCS7_TOKEN11);

            } else if (spConstants.getWssX509PkiPathV1Token10().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10);

            } else if (spConstants.getWssX509PkiPathV1Token11().equals(name)) {
                parent.setTokenVersionAndType(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11);

            }
        }
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }
}
