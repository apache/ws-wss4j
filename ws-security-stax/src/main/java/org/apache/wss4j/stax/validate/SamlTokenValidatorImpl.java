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
package org.apache.wss4j.stax.validate;

import java.util.Date;
import java.util.List;

import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.stax.securityToken.SamlSecurityToken;
import org.apache.wss4j.stax.impl.securityToken.SamlSecurityTokenImpl;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;

public class SamlTokenValidatorImpl extends SignatureTokenValidatorImpl implements SamlTokenValidator {
    
    private static final transient org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlTokenValidatorImpl.class);
                                          
    /**
     * The time in seconds in the future within which the NotBefore time of an incoming
     * Assertion is valid. The default is 60 seconds.
     */
    private int futureTTL = 60;
    
    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    private boolean validateSignatureAgainstProfile = true;
    
    /**
     * If this is set, then the value must appear as one of the Subject Confirmation Methods
     */
    private String requiredSubjectConfirmationMethod;
    
    /**
     * If this is set, at least one of the standard Subject Confirmation Methods *must*
     * be present in the assertion (Bearer / SenderVouches / HolderOfKey).
     */
    private boolean requireStandardSubjectConfirmationMethod = true;
    
    /**
     * If this is set, an Assertion with a Bearer SubjectConfirmation Method must be
     * signed 
     */
    private boolean requireBearerSignature = true;

    /**
     * Set the time in seconds in the future within which the NotBefore time of an incoming
     * Assertion is valid. The default is 60 seconds.
     */
    public void setFutureTTL(int newFutureTTL) {
        futureTTL = newFutureTTL;
    }
    
    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public boolean isValidateSignatureAgainstProfile() {
        return validateSignatureAgainstProfile;
    }

    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public void setValidateSignatureAgainstProfile(boolean validateSignatureAgainstProfile) {
        this.validateSignatureAgainstProfile = validateSignatureAgainstProfile;
    }
    
    public String getRequiredSubjectConfirmationMethod() {
        return requiredSubjectConfirmationMethod;
    }

    public void setRequiredSubjectConfirmationMethod(String requiredSubjectConfirmationMethod) {
        this.requiredSubjectConfirmationMethod = requiredSubjectConfirmationMethod;
    }

    @Override
    public <T extends SamlSecurityToken & InboundSecurityToken> T validate(final SamlAssertionWrapper samlAssertionWrapper,
                                                 final InboundSecurityToken subjectSecurityToken,
                                                 final TokenContext tokenContext) throws WSSecurityException {
        // Check conditions
        checkConditions(samlAssertionWrapper,
                        tokenContext.getWssSecurityProperties().getAudienceRestrictions());
        
        // Check the AuthnStatements of the assertion (if any)
        checkAuthnStatements(samlAssertionWrapper);
        
        // Check the Subject Confirmation requirements
        verifySubjectConfirmationMethod(samlAssertionWrapper);
        
        // Check OneTimeUse Condition
        checkOneTimeUse(samlAssertionWrapper, 
                        tokenContext.getWssSecurityProperties().getSamlOneTimeUseReplayCache());
        
        // Validate the assertion against schemas/profiles
        validateAssertion(samlAssertionWrapper);

        Crypto sigVerCrypto = null;
        if (samlAssertionWrapper.isSigned()) {
            sigVerCrypto = tokenContext.getWssSecurityProperties().getSignatureVerificationCrypto();
        }
        SamlSecurityTokenImpl securityToken = new SamlSecurityTokenImpl(
                samlAssertionWrapper, subjectSecurityToken,
                tokenContext.getWsSecurityContext(),
                sigVerCrypto,
                WSSecurityTokenConstants.KeyIdentifier_NoKeyInfo,
                tokenContext.getWssSecurityProperties());

        securityToken.setElementPath(tokenContext.getElementPath());
        securityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
        @SuppressWarnings("unchecked")
        T token = (T)securityToken;
        return token;
    }

    /**
     * Check the Subject Confirmation method requirements
     */
    protected void verifySubjectConfirmationMethod(
        SamlAssertionWrapper samlAssertion
    ) throws WSSecurityException {
        
        List<String> methods = samlAssertion.getConfirmationMethods();
        if (methods == null || methods.isEmpty()) {
            if (requiredSubjectConfirmationMethod != null) {
                LOG.debug("A required subject confirmation method was not present");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                          "invalidSAMLsecurity");
            } else if (requireStandardSubjectConfirmationMethod) {
                LOG.debug("A standard subject confirmation method was not present");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                          "invalidSAMLsecurity");
            }
        }
        
        boolean signed = samlAssertion.isSigned();
        boolean requiredMethodFound = false;
        boolean standardMethodFound = false;
        for (String method : methods) {
            // The assertion must have been signed for HOK
            if (OpenSAMLUtil.isMethodHolderOfKey(method)) {
                if (!signed) {
                    LOG.debug("A holder-of-key assertion must be signed");
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                                  "invalidSAMLsecurity");
                }
                standardMethodFound = true;
            }
            
            if (method != null) {
                if (method.equals(requiredSubjectConfirmationMethod)) {
                    requiredMethodFound = true;
                }
                if (SAML2Constants.CONF_BEARER.equals(method)
                    || SAML1Constants.CONF_BEARER.equals(method)) {
                    standardMethodFound = true;
                    if (requireBearerSignature && !signed) {
                        LOG.debug("A Bearer Assertion was not signed");
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                                      "invalidSAMLsecurity");
                    }
                } else if (SAML2Constants.CONF_SENDER_VOUCHES.equals(method)
                    || SAML1Constants.CONF_SENDER_VOUCHES.equals(method)) {
                    standardMethodFound = true;
                }
            }
        }
        
        if (!requiredMethodFound && requiredSubjectConfirmationMethod != null) {
            LOG.debug("A required subject confirmation method was not present");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                          "invalidSAMLsecurity");
        }
        
        if (!standardMethodFound && requireStandardSubjectConfirmationMethod) {
            LOG.debug("A standard subject confirmation method was not present");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, 
                                      "invalidSAMLsecurity");
        }
    }
    
    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(
        SamlAssertionWrapper samlAssertion, List<String> audienceRestrictions
    ) throws WSSecurityException {
        checkConditions(samlAssertion);
        samlAssertion.checkAudienceRestrictions(audienceRestrictions);
    }
    
    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.checkConditions(futureTTL);
    }
    
    /**
     * Check the AuthnStatements of the Assertion (if any)
     */
    protected void checkAuthnStatements(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.checkAuthnStatements(futureTTL);
    }
    
    /**
     * Check the "OneTimeUse" Condition of the Assertion. If this is set then the Assertion
     * is cached (if a cache is defined), and must not have been previously cached
     */
    protected void checkOneTimeUse(
        SamlAssertionWrapper samlAssertion, ReplayCache replayCache
    ) throws WSSecurityException {
        if (replayCache != null
            && samlAssertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && samlAssertion.getSaml2().getConditions() != null
            && samlAssertion.getSaml2().getConditions().getOneTimeUse() != null) {
            String identifier = samlAssertion.getId();
            
            if (replayCache.contains(identifier)) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "badSamlToken",
                    "A replay attack has been detected");
            }
            
            DateTime expires = samlAssertion.getSaml2().getConditions().getNotOnOrAfter();
            if (expires != null) {
                Date rightNow = new Date();
                long currentTime = rightNow.getTime();
                long expiresTime = expires.getMillis();
                replayCache.add(identifier, 1L + (expiresTime - currentTime) / 1000L);
            } else {
                replayCache.add(identifier);
            }
        }
    }
    
    /**
     * Validate the samlAssertion against schemas/profiles
     */
    protected void validateAssertion(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.validateAssertion(validateSignatureAgainstProfile);
    }

    public boolean isRequireStandardSubjectConfirmationMethod() {
        return requireStandardSubjectConfirmationMethod;
    }

    public void setRequireStandardSubjectConfirmationMethod(boolean requireStandardSubjectConfirmationMethod) {
        this.requireStandardSubjectConfirmationMethod = requireStandardSubjectConfirmationMethod;
    }

    public boolean isRequireBearerSignature() {
        return requireBearerSignature;
    }

    public void setRequireBearerSignature(boolean requireBearerSignature) {
        this.requireBearerSignature = requireBearerSignature;
    }
    
}
