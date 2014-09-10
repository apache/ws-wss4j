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

package org.apache.ws.security.processor;

import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.w3c.dom.Element;

import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.QName;

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
        
        AssertionWrapper samlAssertion = new AssertionWrapper(elem);
        XMLSignature xmlSignature = 
            verifySignatureKeysAndAlgorithms(samlAssertion, data, wsDocInfo);
        List<WSDataRef> dataRefs = createDataRefs(elem, samlAssertion, xmlSignature);
        
        Credential credential = 
            handleSAMLToken(samlAssertion, data, validator, wsDocInfo);
        samlAssertion = credential.getAssertion();
        if (log.isDebugEnabled()) {
            log.debug("SAML Assertion issuer " + samlAssertion.getIssuerString());
            log.debug(DOM2Writer.nodeToString(elem));
        }
        
        // See if the token has been previously processed
        String id = samlAssertion.getId();
        Element foundElement = wsDocInfo.getTokenElement(id);
        if (elem.equals(foundElement)) {
            WSSecurityEngineResult result = wsDocInfo.getResult(id);
            return java.util.Collections.singletonList(result);
        } else if (foundElement != null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, "duplicateError"
            );
        }

        wsDocInfo.addTokenElement(elem);
        WSSecurityEngineResult result = null;
        if (samlAssertion.isSigned()) {
            result = new WSSecurityEngineResult(WSConstants.ST_SIGNED, samlAssertion);
            result.put(WSSecurityEngineResult.TAG_DATA_REF_URIS, dataRefs);
        } else {
            result = new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, samlAssertion);
        }
        
        if (!"".equals(id)) {
            result.put(WSSecurityEngineResult.TAG_ID, id);
        }

        if (validator != null) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            if (credential.getTransformedToken() != null) {
                result.put(
                    WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN, credential.getTransformedToken()
                );
                if (credential.getPrincipal() != null) {
                    result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
                } else {
                    SAMLTokenPrincipal samlPrincipal =
                        new SAMLTokenPrincipal(credential.getTransformedToken());
                    result.put(WSSecurityEngineResult.TAG_PRINCIPAL, samlPrincipal);
                }
            } else if (credential.getPrincipal() != null) {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
            } else {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, new SAMLTokenPrincipal(samlAssertion));
            }
            result.put(WSSecurityEngineResult.TAG_SUBJECT, credential.getSubject());
        }
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    public Credential handleSAMLToken(
        AssertionWrapper samlAssertion, 
        RequestData data,
        Validator validator,
        WSDocInfo docInfo
    ) throws WSSecurityException {
        // Parse the subject if it exists
        samlAssertion.parseHOKSubject(data, docInfo);
            
        // Now delegate the rest of the verification to the Validator
        Credential credential = new Credential();
        credential.setAssertion(samlAssertion);
        if (validator != null) {
            return validator.validate(credential, data);
        }
        return credential;
    }
    
    private XMLSignature verifySignatureKeysAndAlgorithms(
        AssertionWrapper samlAssertion,
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (samlAssertion.isSigned()) {
            Signature sig = samlAssertion.getSignature();
            KeyInfo keyInfo = sig.getKeyInfo();
            if (keyInfo == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate or key"}
                );
            }
            SAMLKeyInfo samlKeyInfo = 
                SAMLUtil.getCredentialFromKeyInfo(
                    keyInfo.getDOM(), data, wsDocInfo, data.getWssConfig().isWsiBSPCompliant()
                );
            
            PublicKey key = null;
            if (samlKeyInfo.getCerts() != null && samlKeyInfo.getCerts()[0] != null) {
                key = samlKeyInfo.getCerts()[0].getPublicKey();
            } else if (samlKeyInfo.getPublicKey() != null) {
                key = samlKeyInfo.getPublicKey();
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate or key"}
                );
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
                    WSSecurityException.FAILED_CHECK, "invalidSAMLsecurity", 
                    new Object[]{"cannot get certificate or key"}, ex
                );
            }
            
            // Check for compliance against the defined AlgorithmSuite
            AlgorithmSuite algorithmSuite = data.getSamlAlgorithmSuite();
            if (algorithmSuite != null) {
                AlgorithmSuiteValidator algorithmSuiteValidator = new
                    AlgorithmSuiteValidator(algorithmSuite);

                algorithmSuiteValidator.checkSignatureAlgorithms(xmlSignature);
                algorithmSuiteValidator.checkAsymmetricKeyLength(key);
            }

            samlAssertion.verifySignature(samlKeyInfo);
            
            return xmlSignature;
        }
        
        return null;
    }

    private List<WSDataRef> createDataRefs(
        Element token, AssertionWrapper samlAssertion, XMLSignature xmlSignature
    ) {
        if (xmlSignature == null) {
            return null;
        }
        
        List<WSDataRef> protectedRefs = new ArrayList<WSDataRef>();
        String signatureMethod = 
            xmlSignature.getSignedInfo().getSignatureMethod().getAlgorithm();
        
        for (Object refObject : xmlSignature.getSignedInfo().getReferences()) {
            Reference reference = (Reference)refObject;
            
            if ("".equals(reference.getURI()) 
                || reference.getURI().equals(samlAssertion.getId())
                || reference.getURI().equals("#" + samlAssertion.getId())) {
                WSDataRef ref = new WSDataRef();
                ref.setWsuId(reference.getURI());
                ref.setProtectedElement(token);
                ref.setAlgorithm(signatureMethod);
                ref.setDigestAlgorithm(reference.getDigestMethod().getAlgorithm());
    
                // Set the Transform algorithms as well
                @SuppressWarnings("unchecked")
                List<Transform> transforms = (List<Transform>)reference.getTransforms();
                List<String> transformAlgorithms = new ArrayList<String>(transforms.size());
                for (Transform transform : transforms) {
                    transformAlgorithms.add(transform.getAlgorithm());
                }
                ref.setTransformAlgorithms(transformAlgorithms);
    
                ref.setXpath(ReferenceListProcessor.getXPath(token));
                protectedRefs.add(ref);
            }
        }
        
        return protectedRefs;
    }
}
