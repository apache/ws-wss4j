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
package org.swssf.wss.ext;

import org.apache.xml.security.stax.crypto.Crypto;
import org.apache.xml.security.stax.crypto.MerlinBase;
import org.apache.xml.security.stax.ext.XMLSecurityConfigurationException;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;

import java.net.URL;
import java.security.KeyStore;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Main configuration class to supply keys etc.
 * This class is subject to change in the future.
 * Probably we will allow to configure the framework per WSDL
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSSecurityProperties extends XMLSecurityProperties {

    private WSSConstants.KeyIdentifierType signatureKeyIdentifierType;
    private WSSConstants.KeyIdentifierType encryptionKeyIdentifierType;

    public WSSConstants.KeyIdentifierType getSignatureKeyIdentifierType() {
        return signatureKeyIdentifierType;
    }

    public void setSignatureKeyIdentifierType(WSSConstants.KeyIdentifierType signatureKeyIdentifierType) {
        this.signatureKeyIdentifierType = signatureKeyIdentifierType;
    }

    /**
     * returns the KeyIdentifierType which will be used in the secured document
     *
     * @return The KeyIdentifierType
     */
    public WSSConstants.KeyIdentifierType getEncryptionKeyIdentifierType() {
        return encryptionKeyIdentifierType;
    }

    /**
     * Specifies the KeyIdentifierType to use in the secured document
     *
     * @param encryptionKeyIdentifierType
     */
    public void setEncryptionKeyIdentifierType(WSSConstants.KeyIdentifierType encryptionKeyIdentifierType) {
        this.encryptionKeyIdentifierType = encryptionKeyIdentifierType;
    }

    private Integer timestampTTL = 300;

    public Integer getTimestampTTL() {
        return timestampTTL;
    }

    public void setTimestampTTL(Integer timestampTTL) {
        this.timestampTTL = timestampTTL;
    }

    private boolean strictTimestampCheck = true;

    public boolean isStrictTimestampCheck() {
        return strictTimestampCheck;
    }

    public void setStrictTimestampCheck(boolean strictTimestampCheck) {
        this.strictTimestampCheck = strictTimestampCheck;
    }

    private String tokenUser;
    private WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType;

    public String getTokenUser() {
        return tokenUser;
    }

    public void setTokenUser(String tokenUser) {
        this.tokenUser = tokenUser;
    }

    public WSSConstants.UsernameTokenPasswordType getUsernameTokenPasswordType() {
        return usernameTokenPasswordType;
    }

    public void setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType) {
        this.usernameTokenPasswordType = usernameTokenPasswordType;
    }

    private boolean enableSignatureConfirmationVerification = false;

    public boolean isEnableSignatureConfirmationVerification() {
        return enableSignatureConfirmationVerification;
    }

    public void setEnableSignatureConfirmationVerification(boolean enableSignatureConfirmationVerification) {
        this.enableSignatureConfirmationVerification = enableSignatureConfirmationVerification;
    }

    private boolean useReqSigCertForEncryption = false;

    public boolean isUseReqSigCertForEncryption() {
        return useReqSigCertForEncryption;
    }

    public void setUseReqSigCertForEncryption(boolean useReqSigCertForEncryption) {
        this.useReqSigCertForEncryption = useReqSigCertForEncryption;
    }

    private String actor;

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }


    private WSSConstants.KeyIdentifierType derivedKeyKeyIdentifierType;
    private WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference;

    public WSSConstants.KeyIdentifierType getDerivedKeyKeyIdentifierType() {
        return derivedKeyKeyIdentifierType;
    }

    public void setDerivedKeyKeyIdentifierType(WSSConstants.KeyIdentifierType derivedKeyKeyIdentifierType) {
        this.derivedKeyKeyIdentifierType = derivedKeyKeyIdentifierType;
    }

    public WSSConstants.DerivedKeyTokenReference getDerivedKeyTokenReference() {
        return derivedKeyTokenReference;
    }

    public void setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference) {
        this.derivedKeyTokenReference = derivedKeyTokenReference;
    }

    private final List<WSSConstants.BSPRule> ignoredBSPRules = new LinkedList<WSSConstants.BSPRule>();

    public void addIgnoreBSPRule(WSSConstants.BSPRule bspRule) {
        ignoredBSPRules.add(bspRule);
    }

    public List<WSSConstants.BSPRule> getIgnoredBSPRules() {
        return Collections.unmodifiableList(ignoredBSPRules);
    }
    
    private Class<? extends MerlinBase> signatureCryptoClass;
    private KeyStore signatureKeyStore;
    private String signatureUser;
    
    public void setSignatureUser(String signatureUser) {
        this.signatureUser = signatureUser;
    }

    public String getSignatureUser() {
        return signatureUser;
    }
    
    public KeyStore getSignatureKeyStore() {
        return signatureKeyStore;
    }

    public void loadSignatureKeyStore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        this.signatureKeyStore = keyStore;
    }

    public Class<? extends MerlinBase> getSignatureCryptoClass() {
        if (signatureCryptoClass != null) {
            return signatureCryptoClass;
        }
        signatureCryptoClass = org.apache.xml.security.stax.crypto.Merlin.class;
        return signatureCryptoClass;
    }

    public void setSignatureCryptoClass(Class<? extends MerlinBase> signatureCryptoClass) {
        this.signatureCryptoClass = signatureCryptoClass;
    }
    
    private Crypto cachedSignatureCrypto;
    private KeyStore cachedSignatureKeyStore;

    public Crypto getSignatureCrypto() throws XMLSecurityException {

        if (this.getSignatureKeyStore() == null) {
            throw new XMLSecurityConfigurationException(XMLSecurityException.ErrorCode.FAILURE, "signatureKeyStoreNotSet");
        }

        if (this.getSignatureKeyStore() == cachedSignatureKeyStore) {
            return cachedSignatureCrypto;
        }

        Class<? extends MerlinBase> signatureCryptoClass = this.getSignatureCryptoClass();

        try {
            MerlinBase signatureCrypto = signatureCryptoClass.newInstance();
            signatureCrypto.setKeyStore(this.getSignatureKeyStore());
            cachedSignatureCrypto = signatureCrypto;
            cachedSignatureKeyStore = this.getSignatureKeyStore();
            return signatureCrypto;
        } catch (Exception e) {
            throw new XMLSecurityConfigurationException(XMLSecurityException.ErrorCode.FAILURE, "signatureCryptoFailure", e);
        }
    }
    
    private Class<? extends MerlinBase> signatureVerificationCryptoClass;
    private KeyStore signatureVerificationKeyStore;

    public KeyStore getSignatureVerificationKeyStore() {
        return signatureVerificationKeyStore;
    }

    public void loadSignatureVerificationKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        this.signatureVerificationKeyStore = keyStore;
    }

    public Class<? extends MerlinBase> getSignatureVerificationCryptoClass() {
        if (signatureVerificationCryptoClass != null) {
            return signatureVerificationCryptoClass;
        }
        signatureVerificationCryptoClass = org.apache.xml.security.stax.crypto.Merlin.class;
        return signatureVerificationCryptoClass;
    }

    public void setSignatureVerificationCryptoClass(Class<? extends MerlinBase> signatureVerificationCryptoClass) {
        this.signatureVerificationCryptoClass = signatureVerificationCryptoClass;
    }

    private Crypto cachedSignatureVerificationCrypto;
    private KeyStore cachedSignatureVerificationKeyStore;

    public Crypto getSignatureVerificationCrypto() throws XMLSecurityException {

        if (this.getSignatureVerificationKeyStore() == null) {
            throw new XMLSecurityConfigurationException(XMLSecurityException.ErrorCode.FAILURE, "signatureVerificationKeyStoreNotSet");
        }

        if (this.getSignatureVerificationKeyStore() == cachedSignatureVerificationKeyStore) {
            return cachedSignatureVerificationCrypto;
        }

        Class<? extends MerlinBase> signatureVerificationCryptoClass = this.getSignatureVerificationCryptoClass();

        try {
            MerlinBase signatureVerificationCrypto = signatureVerificationCryptoClass.newInstance();
            signatureVerificationCrypto.setKeyStore(this.getSignatureVerificationKeyStore());
            cachedSignatureVerificationCrypto = signatureVerificationCrypto;
            cachedSignatureVerificationKeyStore = this.getSignatureVerificationKeyStore();
            return signatureVerificationCrypto;
        } catch (Exception e) {
            throw new XMLSecurityConfigurationException(XMLSecurityException.ErrorCode.FAILURE, "signatureVerificationCryptoFailure", e);
        }
    }
}
