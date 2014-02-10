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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.w3c.dom.Element;

/**
 * This abstract class encapsulates configuration for Signature + Encryption Actions.
 */
public abstract class SignatureEncryptionActionToken implements SecurityActionToken {
    
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureEncryptionActionToken.class);

    private X509Certificate certificate;
    private byte[] key;
    private String user;
    private Element keyInfoElement;
    private Crypto crypto;
    private String keyIdentifier;
    private int keyIdentifierId;
    private String digestAlgorithm;
    private List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
    private String optionalParts;
    private String cryptoProperties;
    private String tokenType;
    private String tokenId;
    private String sha1Value;
    private String derivedKeyTokenReference;
    private int derivedKeyLength;
    
    public X509Certificate getCertificate() {
        return certificate;
    }
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }
    public byte[] getKey() {
        return key;
    }
    public void setKey(byte[] key) {
        this.key = key;
    }
    public Element getKeyInfoElement() {
        return keyInfoElement;
    }
    public void setKeyInfoElement(Element keyInfoElement) {
        this.keyInfoElement = keyInfoElement;
    }
    public String getUser() {
        return user;
    }
    public void setUser(String user) {
        this.user = user;
    }
    
    public synchronized Crypto getCrypto() throws WSSecurityException {
        if (crypto != null) {
            return crypto;
        }
        if (cryptoProperties != null) {
            ClassLoader classLoader = null;
            try {
                classLoader = Loader.getTCL();
            } catch (Exception ex) {
                // Ignore
                LOG.debug(ex.getMessage(), ex);
            }
            Properties properties = CryptoFactory.getProperties(cryptoProperties, classLoader);
            crypto = 
                CryptoFactory.getInstance(properties, classLoader, null);
        }
        return crypto;
    }
    
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }
    public String getKeyIdentifier() {
        return keyIdentifier;
    }
    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }
    public String getOptionalParts() {
        return optionalParts;
    }
    public void setOptionalParts(String optionalParts) {
        this.optionalParts = optionalParts;
    }
    public int getKeyIdentifierId() {
        return keyIdentifierId;
    }
    public void setKeyIdentifierId(int keyIdentifierId) {
        this.keyIdentifierId = keyIdentifierId;
    }
    public List<WSEncryptionPart> getParts() {
        return parts;
    }
    public void setParts(List<WSEncryptionPart> parts) {
        this.parts = parts;
    }
    public String getCryptoProperties() {
        return cryptoProperties;
    }
    public void setCryptoProperties(String cryptoProperties) {
        this.cryptoProperties = cryptoProperties;
    }
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public String getTokenId() {
        return tokenId;
    }
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }
    public String getSha1Value() {
        return sha1Value;
    }
    public void setSha1Value(String sha1Value) {
        this.sha1Value = sha1Value;
    }
    public String getDerivedKeyTokenReference() {
        return derivedKeyTokenReference;
    }
    public void setDerivedKeyTokenReference(String derivedKeyTokenReference) {
        this.derivedKeyTokenReference = derivedKeyTokenReference;
    }
    public int getDerivedKeyLength() {
        return derivedKeyLength;
    }
    public void setDerivedKeyLength(int derivedKeyLength) {
        this.derivedKeyLength = derivedKeyLength;
    }
}

