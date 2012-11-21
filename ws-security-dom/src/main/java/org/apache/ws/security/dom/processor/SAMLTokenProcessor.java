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

package org.apache.ws.security.dom.processor;

import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import org.apache.ws.security.dom.SAMLTokenPrincipal;
import org.apache.ws.security.dom.WSConstants;
import org.apache.ws.security.dom.WSDocInfo;
import org.apache.ws.security.dom.WSSecurityEngine;
import org.apache.ws.security.dom.WSSecurityEngineResult;
import org.apache.ws.security.common.crypto.AlgorithmSuite;
import org.apache.ws.security.common.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.AssertionWrapper;
import org.apache.ws.security.common.saml.SAMLKeyInfo;
import org.apache.ws.security.common.saml.SAMLUtil;
import org.apache.ws.security.common.util.DOM2Writer;
import org.apache.ws.security.dom.handler.RequestData;
import org.apache.ws.security.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.ws.security.dom.validate.Credential;
import org.apache.ws.security.dom.validate.Validator;

import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;

public class SAMLTokenProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(SAMLTokenProcessor.class);
    private XMLSignatureFactory signatureFactory;

    public SAMLTokenProcessor() {
        // Try to install the Santuario Provider - fall back to the JDK provider if this does
        // not work
        try {
            signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            signatureFactory = XMLSignatureFactory.getInstance("DOM");
        }
    }

    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data, 
        WSDocInfo wsDocInfo 
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found SAML Assertion element");
        }
        
        Validator validator = 
            data.getValidator(new QName(elem.getNamespaceURI(), elem.getLocalName()));
        Credential credential = handleSAMLToken(elem, data, validator, wsDocInfo);
        AssertionWrapper assertion = credential.getAssertion();
        if (log.isDebugEnabled()) {
            log.debug("SAML Assertion issuer " + assertion.getIssuerString());
            log.debug(DOM2Writer.nodeToString(elem));
        }
        
        // See if the token has been previously processed
        String id = assertion.getId();
        Element foundElement = wsDocInfo.getTokenElement(id);
        if (elem.equals(foundElement)) {
            WSSecurityEngineResult result = wsDocInfo.getResult(id);
            return java.util.Collections.singletonList(result);
        } else if (foundElement != null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "duplicateError"
            );
        }

        wsDocInfo.addTokenElement(elem);
        WSSecurityEngineResult result = null;
        if (assertion.isSigned()) {
            result = new WSSecurityEngineResult(WSConstants.ST_SIGNED, assertion);
        } else {
            result = new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, assertion);
        }
        
        result.put(WSSecurityEngineResult.TAG_ID, assertion.getId());

        if (validator != null) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            if (credential.getTransformedToken() != null) {
                result.put(
                    WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN, credential.getTransformedToken()
                );
                SAMLTokenPrincipal samlPrincipal = 
                    new SAMLTokenPrincipal(credential.getTransformedToken());
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, samlPrincipal);
            } else if (credential.getPrincipal() != null) {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
            } else {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, new SAMLTokenPrincipal(assertion));
            }
        }
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    public Credential handleSAMLToken(
        Element token, 
        RequestData data,
        Validator validator,
        WSDocInfo docInfo
    ) throws WSSecurityException {
        AssertionWrapper assertion = new AssertionWrapper(token);
        if (assertion.isSigned()) {
            Signature sig = assertion.getSignature();

            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            try {
                profileValidator.validate(sig);
            } catch (ValidationException ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                                              "empty", ex, "SAML signature validation failed");
            }
            
            // Check for compliance against the defined AlgorithmSuite
            AlgorithmSuite algorithmSuite = null;
            if (assertion.getSaml2() != null) {
                algorithmSuite = data.getAlgorithmSuiteMap().get(WSSecurityEngine.SAML2_TOKEN);
            } else {
                algorithmSuite = data.getAlgorithmSuiteMap().get(WSSecurityEngine.SAML_TOKEN);
            }
            
            KeyInfo keyInfo = sig.getKeyInfo();
            SAMLKeyInfo samlKeyInfo = 
                SAMLUtil.getCredentialFromKeyInfo(
                    keyInfo.getDOM(), 
                    new WSSSAMLKeyInfoProcessor(data, docInfo),
                    data.getSigVerCrypto()
                );
            
            if (algorithmSuite != null) {
                AlgorithmSuiteValidator algorithmSuiteValidator = new
                    AlgorithmSuiteValidator(algorithmSuite);

                PublicKey key = null;
                if (samlKeyInfo.getCerts() != null && samlKeyInfo.getCerts()[0] != null) {
                    key = samlKeyInfo.getCerts()[0].getPublicKey();
                } else if (samlKeyInfo.getPublicKey() != null) {
                    key = samlKeyInfo.getPublicKey();
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                        new Object[]{"cannot get certificate or key"}
                    );
                }
            
                // Not checking signature here, just marshalling into an XMLSignature
                // structure for testing the transform/digest algorithms etc.
                XMLValidateContext context = new DOMValidateContext(key, sig.getDOM());
                context.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);

                XMLSignature xmlSignature;
                try {
                    xmlSignature = signatureFactory.unmarshalXMLSignature(context);
                } catch (MarshalException ex) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, "invalidSAMLsecurity", 
                        new Object[]{"cannot get certificate or key"}, ex
                    );
                }

                algorithmSuiteValidator.checkSignatureAlgorithms(xmlSignature);
                algorithmSuiteValidator.checkAsymmetricKeyLength(key);
            }

            assertion.verifySignature(samlKeyInfo);
        }
        // Parse the HOK subject if it exists
        assertion.parseHOKSubject( 
            new WSSSAMLKeyInfoProcessor(data, docInfo), data.getSigVerCrypto(), 
            data.getCallbackHandler()
        );
            
        // Now delegate the rest of the verification to the Validator
        Credential credential = new Credential();
        credential.setAssertion(assertion);
        if (validator != null) {
            return validator.validate(credential, data);
        }
        return credential;
    }

}
