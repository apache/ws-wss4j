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
package org.apache.ws.security.stax.validate;

import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.SamlAssertionWrapper;
import org.apache.ws.security.stax.impl.securityToken.SAMLSecurityToken;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SamlTokenValidatorImpl extends SignatureTokenValidatorImpl implements SamlTokenValidator {

    /**
     * The time in seconds in the future within which the NotBefore time of an incoming
     * Assertion is valid. The default is 60 seconds.
     */
    private int futureTTL = 60;

    /**
     * Set the time in seconds in the future within which the NotBefore time of an incoming
     * Assertion is valid. The default is 60 seconds.
     */
    public void setFutureTTL(int newFutureTTL) {
        futureTTL = newFutureTTL;
    }

    @Override
    public AbstractInboundSecurityToken validate(final SamlAssertionWrapper samlAssertionWrapper,
                                                 final SecurityToken subjectSecurityToken,
                                                 final TokenContext tokenContext) throws WSSecurityException {
        // Check conditions
        checkConditions(samlAssertionWrapper);
        // Validate the assertion against schemas/profiles
        validateAssertion(samlAssertionWrapper);

        AbstractInboundSecurityToken securityToken = new SAMLSecurityToken(
                samlAssertionWrapper, subjectSecurityToken,
                tokenContext.getWsSecurityContext(),
                tokenContext.getWssSecurityProperties().getSignatureVerificationCrypto(),
                samlAssertionWrapper.getId(), null);

        securityToken.setElementPath(tokenContext.getElementPath());
        securityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
        return securityToken;
    }

    /**
     * Check the Conditions of the Assertion.
     */
    //todo shoudn't we move this into the SamlAssertionWrapper? Then it could be reused by StAX and DOM impl.
    protected void checkConditions(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (samlAssertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
                && samlAssertion.getSaml2().getConditions() != null) {
            validFrom = samlAssertion.getSaml2().getConditions().getNotBefore();
            validTill = samlAssertion.getSaml2().getConditions().getNotOnOrAfter();
        } else if (samlAssertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
                && samlAssertion.getSaml1().getConditions() != null) {
            validFrom = samlAssertion.getSaml1().getConditions().getNotBefore();
            validTill = samlAssertion.getSaml1().getConditions().getNotOnOrAfter();
        }

        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(futureTTL);
            if (validFrom.isAfter(currentTime)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", "SAML Token condition (Not Before) not met");
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                    "empty", "SAML Token condition (Not On Or After) not met");
        }
    }

    /**
     * Validate the assertion against schemas/profiles
     */
    //todo shoudn't we move this into the SamlAssertionWrapper? Then it could be reused by StAX and DOM impl.
    protected void validateAssertion(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.validateSignatureAgainstProfile();
        
        if (samlAssertion.getSaml1() != null) {
            ValidatorSuite schemaValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml1-schema-validator");
            ValidatorSuite specValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml1-spec-validator");
            try {
                schemaValidators.validate(samlAssertion.getSaml1());
                specValidators.validate(samlAssertion.getSaml1());
            } catch (ValidationException e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "empty", e, "Saml Validation error: "
                );
            }
        } else if (samlAssertion.getSaml2() != null) {
            ValidatorSuite schemaValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
            ValidatorSuite specValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml2-core-spec-validator");
            try {
                schemaValidators.validate(samlAssertion.getSaml2());
                specValidators.validate(samlAssertion.getSaml2());
            } catch (ValidationException e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity", e, "Saml Validation error: "
                );
            }
        }
    }
}
