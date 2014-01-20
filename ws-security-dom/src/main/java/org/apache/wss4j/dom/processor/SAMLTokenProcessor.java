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

package org.apache.wss4j.dom.processor;

import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.principal.SAMLTokenPrincipalImpl;
import org.w3c.dom.Element;

import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;

public class SAMLTokenProcessor implements Processor {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SAMLTokenProcessor.class);
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
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found SAML Assertion element");
        }
        
        Validator validator = 
            data.getValidator(new QName(elem.getNamespaceURI(), elem.getLocalName()));
        Credential credential = handleSAMLToken(elem, data, validator, wsDocInfo);
        SamlAssertionWrapper samlAssertion = credential.getSamlAssertion();
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML Assertion issuer " + samlAssertion.getIssuerString());
            LOG.debug(DOM2Writer.nodeToString(elem));
        }
        
        // See if the token has been previously processed
        String id = samlAssertion.getId();
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
        if (samlAssertion.isSigned()) {
            result = new WSSecurityEngineResult(WSConstants.ST_SIGNED, samlAssertion);
        } else {
            result = new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, samlAssertion);
        }
        
        result.put(WSSecurityEngineResult.TAG_ID, samlAssertion.getId());

        if (validator != null) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            if (credential.getTransformedToken() != null) {
                result.put(
                    WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN, credential.getTransformedToken()
                );
                SAMLTokenPrincipalImpl samlPrincipal =
                    new SAMLTokenPrincipalImpl(credential.getTransformedToken());
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, samlPrincipal);
            } else if (credential.getPrincipal() != null) {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
            } else {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, new SAMLTokenPrincipalImpl(samlAssertion));
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
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(token);
        if (samlAssertion.isSigned()) {
            // Check for compliance against the defined AlgorithmSuite
            AlgorithmSuite algorithmSuite = data.getSamlAlgorithmSuite();
            
            Signature sig = samlAssertion.getSignature();
            KeyInfo keyInfo = sig.getKeyInfo();
            if (keyInfo == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                    "cannot get certificate or key"
                );
            }
            SAMLKeyInfo samlKeyInfo = 
                SAMLUtil.getCredentialFromKeyInfo(
                    keyInfo.getDOM(), new WSSSAMLKeyInfoProcessor(data, docInfo), data.getSigVerCrypto()
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
                        "cannot get certificate or key");
                }
            
                // Not checking signature here, just marshalling into an XMLSignature
                // structure for testing the transform/digest algorithms etc.
                XMLValidateContext context = new DOMValidateContext(key, sig.getDOM());
                context.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);

                XMLSignature xmlSignature;
                try {
                    xmlSignature = signatureFactory.unmarshalXMLSignature(context);
                } catch (MarshalException ex) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, "invalidSAMLsecurity", 
                        ex, "cannot get certificate or key"
                    );
                }

                algorithmSuiteValidator.checkSignatureAlgorithms(xmlSignature);
                algorithmSuiteValidator.checkAsymmetricKeyLength(key);
            }

            samlAssertion.verifySignature(samlKeyInfo);
        }
        // Parse the subject if it exists
        samlAssertion.parseSubject(
            new WSSSAMLKeyInfoProcessor(data, docInfo), data.getSigVerCrypto(), 
            data.getCallbackHandler()
        );
            
        // Now delegate the rest of the verification to the Validator
        Credential credential = new Credential();
        credential.setSamlAssertion(samlAssertion);
        if (validator != null) {
            return validator.validate(credential, data);
        }
        return credential;
    }

}
