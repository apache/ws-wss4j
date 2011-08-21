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

import javax.crypto.Mac;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class HMACSignatureAlgorithm implements SignatureAlgorithm {

    private AlgorithmType algorithmType;
    private Mac mac;

    public HMACSignatureAlgorithm(AlgorithmType algorithmType) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.algorithmType = algorithmType;
        mac = Mac.getInstance(algorithmType.getJCEName(), algorithmType.getJCEProvider());
    }

    public void engineUpdate(byte[] input) throws WSSecurityException {
        mac.update(input);
    }

    public void engineUpdate(byte input) throws WSSecurityException {
        mac.update(input);
    }

    public void engineUpdate(byte[] buf, int offset, int len) throws WSSecurityException {
        mac.update(buf, offset, len);
    }

    public void engineInitSign(Key signingKey) throws WSSecurityException {
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException {
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException {
        try {
            mac.init(signingKey, algorithmParameterSpec);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public byte[] engineSign() throws WSSecurityException {
        return mac.doFinal();
    }

    public void engineInitVerify(Key verificationKey) throws WSSecurityException {
        try {
            mac.init(verificationKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public boolean engineVerify(byte[] signature) throws WSSecurityException {
        byte[] completeResult = mac.doFinal();
        return MessageDigest.isEqual(completeResult, signature);
    }

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException {
    }
}
