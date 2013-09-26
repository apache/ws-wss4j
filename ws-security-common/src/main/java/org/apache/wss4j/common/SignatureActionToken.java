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
package org.apache.wss4j.common;


/**
 * This class encapsulates configuration for Signature Actions.
 */
public class SignatureActionToken extends SignatureEncryptionActionToken {  

    private String c14nAlgorithm;
    private boolean includeSignatureToken = true;
    private boolean useSingleCert = true;
    private String signatureAlgorithm;
    
    public String getC14nAlgorithm() {
        return c14nAlgorithm;
    }
    public void setC14nAlgorithm(String c14nAlgorithm) {
        this.c14nAlgorithm = c14nAlgorithm;
    }
    public boolean isIncludeSignatureToken() {
        return includeSignatureToken;
    }
    public void setIncludeSignatureToken(boolean includeSignatureToken) {
        this.includeSignatureToken = includeSignatureToken;
    }
    public boolean isUseSingleCert() {
        return useSingleCert;
    }
    public void setUseSingleCert(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
 
}

