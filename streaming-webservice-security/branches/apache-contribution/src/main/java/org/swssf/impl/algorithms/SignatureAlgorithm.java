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

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface SignatureAlgorithm {

    public void engineUpdate(byte[] input) throws WSSecurityException;

    public void engineUpdate(byte input) throws WSSecurityException;

    public void engineUpdate(byte buf[], int offset, int len) throws WSSecurityException;

    public void engineInitSign(Key signingKey) throws WSSecurityException;

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException;

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException;

    public byte[] engineSign() throws WSSecurityException;

    public void engineInitVerify(Key verificationKey) throws WSSecurityException;

    public boolean engineVerify(byte[] signature) throws WSSecurityException;

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException;
}
