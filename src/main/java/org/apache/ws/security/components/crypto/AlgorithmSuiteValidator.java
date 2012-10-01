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

package org.apache.ws.security.components.crypto;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.ws.security.WSSecurityException;

/**
 * Validate signature/encryption/etc. algorithms against an AlgorithmSuite policy.
 */
public class AlgorithmSuiteValidator {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(AlgorithmSuiteValidator.class);
    
    private final AlgorithmSuite algorithmSuite;
    
    public AlgorithmSuiteValidator(
        AlgorithmSuite algorithmSuite
    ) {
        this.algorithmSuite = algorithmSuite;
    }
    
    /**
     * Check the Signature Method
     */
    public void checkSignatureMethod(
        String signatureMethod
    ) throws WSSecurityException {
        Set<String> allowedSignatureMethods = algorithmSuite.getSignatureMethods();
        if (!allowedSignatureMethods.isEmpty()
            && !allowedSignatureMethods.contains(signatureMethod)) {
            LOG.debug(
                "SignatureMethod " + signatureMethod + " does not match required values"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
    
    /**
     * Check the C14n Algorithm
     */
    public void checkC14nAlgorithm(
        String c14nAlgorithm
    ) throws WSSecurityException {
        Set<String> allowedC14nAlgorithms = algorithmSuite.getC14nAlgorithms();
        if (!allowedC14nAlgorithms.isEmpty() && !allowedC14nAlgorithms.contains(c14nAlgorithm)) {
            LOG.debug(
                "C14nMethod " + c14nAlgorithm + " does not match required value"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
    
    /**
     * Check the Signature Algorithms
     */
    public void checkSignatureAlgorithms(
        XMLSignature xmlSignature
    ) throws WSSecurityException {
        // Signature Algorithm
        String signatureMethod = 
            xmlSignature.getSignedInfo().getSignatureMethod().getAlgorithm();
        checkSignatureMethod(signatureMethod);
            
        // C14n Algorithm
        String c14nMethod = 
            xmlSignature.getSignedInfo().getCanonicalizationMethod().getAlgorithm();
        checkC14nAlgorithm(c14nMethod);
        
        for (Object refObject : xmlSignature.getSignedInfo().getReferences()) {
            Reference reference = (Reference)refObject;
            // Digest Algorithm
            String digestMethod = reference.getDigestMethod().getAlgorithm();
            Set<String> allowedDigestAlgorithms = algorithmSuite.getDigestAlgorithms();
            if (!allowedDigestAlgorithms.isEmpty()
                    && !allowedDigestAlgorithms.contains(digestMethod)) {
                LOG.debug(
                    "DigestMethod " + digestMethod + " does not match required value"
                );
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
            }
            
            // Transform Algorithms
            for (int i = 0; i < reference.getTransforms().size(); i++) {
                Transform transform = (Transform)reference.getTransforms().get(i);
                String algorithm = transform.getAlgorithm();
                Set<String> allowedTransformAlgorithms = 
                        algorithmSuite.getTransformAlgorithms();
                if (!allowedTransformAlgorithms.isEmpty() 
                        && !allowedTransformAlgorithms.contains(algorithm)) {
                    LOG.debug(
                        "Transform method " + algorithm + " does not match required value"
                    );
                    throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
                }
            }
        }
    }
    
    public void checkEncryptionKeyWrapAlgorithm(
        String keyWrapAlgorithm
    ) throws WSSecurityException {
        Set<String> keyWrapAlgorithms = algorithmSuite.getKeyWrapAlgorithms();
        if (!keyWrapAlgorithms.isEmpty()
            && !keyWrapAlgorithms.contains(keyWrapAlgorithm)) {
            LOG.debug(
                "The Key transport method does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
    
    public void checkSymmetricEncryptionAlgorithm(
        String symmetricAlgorithm
    ) throws WSSecurityException {
        Set<String> encryptionMethods = algorithmSuite.getEncryptionMethods();
        if (!encryptionMethods.isEmpty()
            && !encryptionMethods.contains(symmetricAlgorithm)) {
            LOG.debug(
                "The encryption algorithm does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }

    /**
     * Check the asymmetric key length
     */
    public void checkAsymmetricKeyLength(
        X509Certificate x509Certificate
    ) throws WSSecurityException {
        if (x509Certificate == null) {
            return;
        }
        
        checkAsymmetricKeyLength(x509Certificate.getPublicKey());
    }
    
    /**
     * Check the asymmetric key length
     */
    public void checkAsymmetricKeyLength(
        PublicKey publicKey
    ) throws WSSecurityException {
        if (publicKey == null) {
            return;
        }
        if (publicKey instanceof RSAPublicKey) {
            int modulus = ((RSAPublicKey)publicKey).getModulus().bitLength();
            if (modulus < algorithmSuite.getMinimumAsymmetricKeyLength()
                || modulus > algorithmSuite.getMaximumAsymmetricKeyLength()) {
                LOG.debug(
                    "The asymmetric key length does not match the requirement"
                );
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
            }
        } else if (publicKey instanceof DSAPublicKey) {
            int length = ((DSAPublicKey)publicKey).getParams().getP().bitLength();
            if (length < algorithmSuite.getMinimumAsymmetricKeyLength()
                || length > algorithmSuite.getMaximumAsymmetricKeyLength()) {
                LOG.debug(
                    "The asymmetric key length does not match the requirement"
                );
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
            }
        } else {
            LOG.debug(
                "An unknown public key was provided"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
    
    /**
     * Check the symmetric key length
     */
    public void checkSymmetricKeyLength(
        int secretKeyLength
    ) throws WSSecurityException {
        if (secretKeyLength < (algorithmSuite.getMinimumSymmetricKeyLength() / 8)
            || secretKeyLength > (algorithmSuite.getMaximumSymmetricKeyLength() / 8)) {
            LOG.debug(
                "The symmetric key length does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
    
    /**
     * Check Signature Derived Key length (in bytes)
     */
    public void checkSignatureDerivedKeyLength(
        int derivedKeyLength
    ) throws WSSecurityException {
        int requiredKeyLength = algorithmSuite.getSignatureDerivedKeyLength();
        if (requiredKeyLength > 0 && (derivedKeyLength / 8) != requiredKeyLength) {
            LOG.debug(
                "The signature derived key length of " + derivedKeyLength + " does not match"
                + "the requirement of " + requiredKeyLength
            );
        }
    }
    
    /**
     * Check Encryption Derived Key length (in bytes)
     */
    public void checkEncryptionDerivedKeyLength(
        int derivedKeyLength
    ) throws WSSecurityException {
        int requiredKeyLength = algorithmSuite.getEncryptionDerivedKeyLength();
        if (requiredKeyLength > 0 && (derivedKeyLength / 8) != requiredKeyLength) {
            LOG.debug(
                "The encryption derived key length of " + derivedKeyLength + " does not match"
                + "the requirement of " + requiredKeyLength
            );
        }
    }
    
    /**
     * Check Derived Key algorithm
     */
    public void checkDerivedKeyAlgorithm(
        String algorithm
    ) throws WSSecurityException {
        Set<String> derivedKeyAlgorithms = algorithmSuite.getDerivedKeyAlgorithms();
        if (!derivedKeyAlgorithms.isEmpty()
            && !derivedKeyAlgorithms.contains(algorithm)) {
            LOG.debug(
                "The Derived Key Algorithm does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
        }
    }
        
}
