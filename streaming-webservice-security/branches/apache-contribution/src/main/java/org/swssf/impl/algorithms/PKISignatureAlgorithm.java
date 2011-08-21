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
package org.swssf.impl.algorithms;

import org.swssf.ext.WSSecurityException;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PKISignatureAlgorithm implements SignatureAlgorithm {

    private AlgorithmType algorithmType;
    private Signature signature;

    public PKISignatureAlgorithm(AlgorithmType algorithmType) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.algorithmType = algorithmType;
        signature = Signature.getInstance(algorithmType.getJCEName(), algorithmType.getJCEProvider());
    }

    public void engineUpdate(byte[] input) throws WSSecurityException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineUpdate(byte input) throws WSSecurityException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineUpdate(byte[] buf, int offset, int len) throws WSSecurityException {
        try {
            signature.update(buf, offset, len);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineInitSign(Key signingKey) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey, secureRandom);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public byte[] engineSign() throws WSSecurityException {
        try {
            return signature.sign();
        } catch (SignatureException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitVerify(Key verificationKey) throws WSSecurityException {
        try {
            signature.initVerify((PublicKey) verificationKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public boolean engineVerify(byte[] signature) throws WSSecurityException {
        try {
            return this.signature.verify(signature);
        } catch (SignatureException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException {
        try {
            signature.setParameter(params);
        } catch (InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }
}
