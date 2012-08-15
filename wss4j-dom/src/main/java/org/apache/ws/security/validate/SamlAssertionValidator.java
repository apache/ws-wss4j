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

package org.apache.ws.security.validate;

import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;

/**
 * This class validates a SAML Assertion, which is wrapped in an "AssertionWrapper" instance.
 * It assumes that the AssertionWrapper instance has already verified the signature on the
 * assertion (done by the SAMLTokenProcessor). It verifies trust in the signature, and also
 * checks that the Subject contains a KeyInfo (and processes it) for the holder-of-key case,
 * and verifies that the Assertion is signed as well for holder-of-key. 
 */
public class SamlAssertionValidator extends SignatureTrustValidator {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlAssertionValidator.class);
    
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
    
    /**
     * Validate the credential argument. It must contain a non-null AssertionWrapper. 
     * A Crypto and a CallbackHandler implementation is also required to be set.
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getAssertion() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        AssertionWrapper assertion = credential.getAssertion();
        
        // Check HOK requirements
        String confirmMethod = null;
        List<String> methods = assertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod)) {
            if (assertion.getSubjectKeyInfo() == null) {
                LOG.debug("There is no Subject KeyInfo to match the holder-of-key subject conf method");
                throw new WSSecurityException(WSSecurityException.FAILURE, "noKeyInSAMLToken");
            }
            // The assertion must have been signed for HOK
            if (!assertion.isSigned()) {
                LOG.debug("A holder-of-key assertion must be signed");
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        }
        
        // Check conditions
        checkConditions(assertion);
        
        // Validate the assertion against schemas/profiles
        validateAssertion(assertion);

        // Verify trust on the signature
        if (assertion.isSigned()) {
            verifySignedAssertion(assertion, data);
        }
        return credential;
    }
    
    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     * @param assertion The signed Assertion
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    protected Credential verifySignedAssertion(
        AssertionWrapper assertion,
        RequestData data
    ) throws WSSecurityException {
        Credential trustCredential = new Credential();
        SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
        trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
        trustCredential.setCertificates(samlKeyInfo.getCerts());
        return super.validate(trustCredential, data);
    }
    
    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(AssertionWrapper assertion) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && assertion.getSaml2().getConditions() != null) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
            && assertion.getSaml1().getConditions() != null) {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }
        
        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(futureTTL);
            if (validFrom.isAfter(currentTime)) {
                LOG.debug("SAML Token condition (Not Before) not met");
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            LOG.debug("SAML Token condition (Not On Or After) not met");
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }
    }
    
    /**
     * Validate the assertion against schemas/profiles
     */
    protected void validateAssertion(AssertionWrapper assertion) throws WSSecurityException {
        if (assertion.getSaml1() != null) {
            ValidatorSuite schemaValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml1-schema-validator");
            ValidatorSuite specValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml1-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml1());
                specValidators.validate(assertion.getSaml1());
            } catch (ValidationException e) {
                LOG.debug("Saml Validation error: " + e.getMessage(), e);
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e
                );
            }
        } else if (assertion.getSaml2() != null) {
            ValidatorSuite schemaValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
            ValidatorSuite specValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml2-core-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml2());
                specValidators.validate(assertion.getSaml2());
            } catch (ValidationException e) {
                LOG.debug("Saml Validation error: " + e.getMessage(), e);
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e
                );
            }
        }
    }
    
}
