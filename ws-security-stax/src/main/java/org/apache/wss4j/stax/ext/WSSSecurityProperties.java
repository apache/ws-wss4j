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
package org.apache.wss4j.stax.ext;

import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.cache.ReplayCacheFactory;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.validate.Validator;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.utils.Base64;

/**
 * Main configuration class to supply keys etc.
 * This class is subject to change in the future.
 * Probably we will allow to configure the framework per WSDL
 */
public class WSSSecurityProperties extends XMLSecurityProperties {

    private String actor;
    private CallbackHandler callbackHandler;
    private final List<BSPRule> ignoredBSPRules = new LinkedList<BSPRule>();
    private boolean disableBSPEnforcement;
    private final Map<QName, Validator> validators = new HashMap<QName, Validator>();

    private Integer timestampTTL = 300;
    private Integer timeStampFutureTTL = 60;
    private boolean strictTimestampCheck = true;
    private Integer utTTL = 300;
    private Integer utFutureTTL = 60;

    /**
     * This variable controls whether types other than PasswordDigest or PasswordText
     * are allowed when processing UsernameTokens.
     *
     * By default this is set to false so that the user doesn't have to explicitly
     * reject custom token types in the callback handler.
     */
    private boolean handleCustomPasswordTypes = false;
    private boolean allowUsernameTokenNoPassword = false;
    private WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType;
    private String tokenUser;

    private WSSecurityTokenConstants.KeyIdentifier derivedKeyKeyIdentifier;
    private WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference;

    private WSSCrypto signatureWSSCrypto;
    private String signatureUser;
    private boolean enableSignatureConfirmationVerification = false;
    private WSSCrypto signatureVerificationWSSCrypto;
    private CertStore crlCertStore;
    private WSSCrypto decryptionWSSCrypto;
    private WSSCrypto encryptionWSSCrypto;
    private String encryptionUser;
    private WSSecurityTokenConstants.KeyIdentifier encryptionKeyIdentifier;
    private boolean useReqSigCertForEncryption = false;
    private String encryptionCompressionAlgorithm;
    private boolean enableRevocation = false;
    private ReplayCache timestampReplayCache;
    private ReplayCache nonceReplayCache;

    public WSSSecurityProperties() {
        super();
        setAddExcC14NInclusivePrefixes(true);
    }

    public WSSSecurityProperties(WSSSecurityProperties wssSecurityProperties) {
        super(wssSecurityProperties);

        this.actor = wssSecurityProperties.actor;
        this.callbackHandler = wssSecurityProperties.callbackHandler;
        this.ignoredBSPRules.addAll(wssSecurityProperties.ignoredBSPRules);
        this.disableBSPEnforcement = wssSecurityProperties.disableBSPEnforcement;
        this.validators.putAll(wssSecurityProperties.validators);
        this.timestampTTL = wssSecurityProperties.timestampTTL;
        this.timeStampFutureTTL = wssSecurityProperties.timeStampFutureTTL;
        this.utTTL = wssSecurityProperties.utTTL;
        this.utFutureTTL = wssSecurityProperties.utFutureTTL;
        this.strictTimestampCheck = wssSecurityProperties.strictTimestampCheck;
        this.handleCustomPasswordTypes = wssSecurityProperties.handleCustomPasswordTypes;
        this.usernameTokenPasswordType = wssSecurityProperties.usernameTokenPasswordType;
        this.allowUsernameTokenNoPassword = wssSecurityProperties.allowUsernameTokenNoPassword;
        this.tokenUser = wssSecurityProperties.tokenUser;
        this.derivedKeyKeyIdentifier = wssSecurityProperties.derivedKeyKeyIdentifier;
        this.derivedKeyTokenReference = wssSecurityProperties.derivedKeyTokenReference;
        this.signatureWSSCrypto = wssSecurityProperties.signatureWSSCrypto;
        this.signatureUser = wssSecurityProperties.signatureUser;
        this.enableSignatureConfirmationVerification = wssSecurityProperties.enableSignatureConfirmationVerification;
        this.signatureVerificationWSSCrypto = wssSecurityProperties.signatureVerificationWSSCrypto;
        this.crlCertStore = wssSecurityProperties.crlCertStore;
        this.decryptionWSSCrypto = wssSecurityProperties.decryptionWSSCrypto;
        this.encryptionWSSCrypto = wssSecurityProperties.encryptionWSSCrypto;
        this.encryptionUser = wssSecurityProperties.encryptionUser;
        this.encryptionKeyIdentifier = wssSecurityProperties.encryptionKeyIdentifier;
        this.useReqSigCertForEncryption = wssSecurityProperties.useReqSigCertForEncryption;
        this.encryptionCompressionAlgorithm = wssSecurityProperties.encryptionCompressionAlgorithm;
        this.enableRevocation = wssSecurityProperties.enableRevocation;
        this.timestampReplayCache = wssSecurityProperties.timestampReplayCache;
        this.nonceReplayCache = wssSecurityProperties.nonceReplayCache;
    }

    /**
     * returns the password callback handler
     *
     * @return
     */
    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }


    /**
     * sets the password callback handler
     *
     * @param callbackHandler
     */
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * returns the KeyIdentifierType which will be used in the secured document
     *
     * @return The KeyIdentifierType
     */
    public WSSecurityTokenConstants.KeyIdentifier getEncryptionKeyIdentifier() {
        return encryptionKeyIdentifier;
    }

    /**
     * Specifies the KeyIdentifierType to use in the secured document
     *
     * @param encryptionKeyIdentifier
     */
    public void setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier encryptionKeyIdentifier) {
        this.encryptionKeyIdentifier = encryptionKeyIdentifier;
    }

    public Integer getTimestampTTL() {
        return timestampTTL;
    }

    public void setTimestampTTL(Integer timestampTTL) {
        this.timestampTTL = timestampTTL;
    }

    public boolean isStrictTimestampCheck() {
        return strictTimestampCheck;
    }


    public void setStrictTimestampCheck(boolean strictTimestampCheck) {
        this.strictTimestampCheck = strictTimestampCheck;
    }

    /**
     * @param handleCustomTypes
     * whether to handle custom UsernameToken password types or not
     */
    public void setHandleCustomPasswordTypes(boolean handleCustomTypes) {
        this.handleCustomPasswordTypes = handleCustomTypes;
    }

    /**
     * @return whether custom UsernameToken password types are allowed or not
     */
    public boolean getHandleCustomPasswordTypes() {
        return handleCustomPasswordTypes;
    }

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

    public boolean isEnableSignatureConfirmationVerification() {
        return enableSignatureConfirmationVerification;
    }

    public void setEnableSignatureConfirmationVerification(boolean enableSignatureConfirmationVerification) {
        this.enableSignatureConfirmationVerification = enableSignatureConfirmationVerification;
    }

    public boolean isUseReqSigCertForEncryption() {
        return useReqSigCertForEncryption;
    }

    public void setUseReqSigCertForEncryption(boolean useReqSigCertForEncryption) {
        this.useReqSigCertForEncryption = useReqSigCertForEncryption;
    }

    public String getActor() {
        return actor;
    }


    public void setActor(String actor) {
        this.actor = actor;
    }

    public WSSecurityTokenConstants.KeyIdentifier getDerivedKeyKeyIdentifier() {
        return derivedKeyKeyIdentifier;
    }

    public void setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier derivedKeyKeyIdentifier) {
        this.derivedKeyKeyIdentifier = derivedKeyKeyIdentifier;
    }

    public WSSConstants.DerivedKeyTokenReference getDerivedKeyTokenReference() {
        return derivedKeyTokenReference;
    }

    public void setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference) {
        this.derivedKeyTokenReference = derivedKeyTokenReference;
    }

    public void addIgnoreBSPRule(BSPRule bspRule) {
        ignoredBSPRules.add(bspRule);
    }

    public List<BSPRule> getIgnoredBSPRules() {
        return Collections.unmodifiableList(ignoredBSPRules);
    }

    public void addValidator(QName qName, Validator validator) {
        validators.put(qName, validator);
    }

    @SuppressWarnings("unchecked")
    public <T extends Validator> T getValidator(QName qName) {
        return (T)validators.get(qName);
    }

    public void setSignatureUser(String signatureUser) {
        this.signatureUser = signatureUser;
    }

    public String getSignatureUser() {
        return signatureUser;
    }

    public KeyStore getSignatureKeyStore() {
        if (signatureWSSCrypto != null) {
            return signatureWSSCrypto.getKeyStore();
        }
        return null;
    }

    public void loadSignatureKeyStore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        signatureWSSCrypto.setKeyStore(keyStore);
    }
    
    public Properties getSignatureCryptoProperties() {
        if (signatureWSSCrypto != null) {
            return signatureWSSCrypto.getCryptoProperties();
        }
        return null;
    }
    
    public void setSignatureCryptoProperties(Properties cryptoProperties) {
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        signatureWSSCrypto.setCryptoProperties(cryptoProperties);
    }

    public Class<? extends Merlin> getSignatureCryptoClass() {
        if (signatureWSSCrypto != null) {
            return signatureWSSCrypto.getCryptoClass();
        }
        return org.apache.wss4j.common.crypto.Merlin.class;
    }

    public void setSignatureCryptoClass(Class<? extends Merlin> signatureCryptoClass) {
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        this.signatureWSSCrypto.setCryptoClass(signatureCryptoClass);
    }

    public Crypto getSignatureCrypto() throws WSSConfigurationException {
        if (signatureWSSCrypto == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "signatureKeyStoreNotSet");
        }

        return signatureWSSCrypto.getCrypto();
    }

    public KeyStore getSignatureVerificationKeyStore() {
        if (signatureVerificationWSSCrypto != null) {
            return signatureVerificationWSSCrypto.getKeyStore();
        }
        return null;
    }

    public void loadSignatureVerificationKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        signatureVerificationWSSCrypto.setKeyStore(keyStore);
    }
    
    public void loadCRLCertStore(URL url) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL)cf.generateCRL(url.openStream());
        this.crlCertStore =
            CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(Collections.singletonList(crl))
            );
    }
    
    public Properties getSignatureVerificationCryptoProperties() {
        if (signatureVerificationWSSCrypto != null) {
            return signatureVerificationWSSCrypto.getCryptoProperties();
        }
        return null;
    }
    
    public void setSignatureVerificationCryptoProperties(Properties cryptoProperties) {
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        signatureVerificationWSSCrypto.setCryptoProperties(cryptoProperties);
    }

    public Class<? extends Merlin> getSignatureVerificationCryptoClass() {
        if (signatureVerificationWSSCrypto != null) {
            return signatureVerificationWSSCrypto.getCryptoClass();
        }
        return org.apache.wss4j.common.crypto.Merlin.class;
    }

    public void setSignatureVerificationCryptoClass(Class<? extends Merlin> signatureVerificationCryptoClass) {
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        this.signatureVerificationWSSCrypto.setCryptoClass(signatureVerificationCryptoClass);
        
    }

    public Crypto getSignatureVerificationCrypto() throws WSSConfigurationException {

        if (signatureVerificationWSSCrypto == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "signatureVerificationKeyStoreNotSet");
        }
        signatureVerificationWSSCrypto.setCrlCertStore(crlCertStore);
        return signatureVerificationWSSCrypto.getCrypto();
    }

    /**
     * Returns the decryption keystore
     *
     * @return A keystore for decryption operation
     */
    public KeyStore getDecryptionKeyStore() {
        if (decryptionWSSCrypto != null) {
            return decryptionWSSCrypto.getKeyStore();
        }
        return null;
    }

    /**
     * loads a java keystore from the given url for decrypt operations
     *
     * @param url              The URL to the keystore
     * @param keyStorePassword The keyStorePassword
     * @throws Exception thrown if something goes wrong while loading the keystore
     */
    public void loadDecryptionKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        if (decryptionWSSCrypto == null) {
            decryptionWSSCrypto = new WSSCrypto();
        }
        decryptionWSSCrypto.setKeyStore(keyStore);
    }
    
    public Properties getDecryptionCryptoProperties() {
        if (decryptionWSSCrypto != null) {
            return decryptionWSSCrypto.getCryptoProperties();
        }
        return null;
    }
    
    public void setDecryptionCryptoProperties(Properties cryptoProperties) {
        if (decryptionWSSCrypto == null) {
            decryptionWSSCrypto = new WSSCrypto();
        }
        decryptionWSSCrypto.setCryptoProperties(cryptoProperties);
    }

    /**
     * Returns the decryption crypto class
     *
     * @return
     */
    public Class<? extends Merlin> getDecryptionCryptoClass() {
        if (decryptionWSSCrypto != null) {
            return decryptionWSSCrypto.getCryptoClass();
        }
        return org.apache.wss4j.common.crypto.Merlin.class;
    }

    /**
     * Sets a custom decryption class
     *
     * @param decryptionCryptoClass
     */
    public void setDecryptionCryptoClass(Class<? extends Merlin> decryptionCryptoClass) {
        if (decryptionWSSCrypto == null) {
            decryptionWSSCrypto = new WSSCrypto();
        }
        decryptionWSSCrypto.setCryptoClass(decryptionCryptoClass);
    }

    /**
     * returns the decryptionCrypto for the key-management
     *
     * @return A Crypto instance
     * @throws WSSConfigurationException thrown if something goes wrong
     */
    public Crypto getDecryptionCrypto() throws WSSConfigurationException {

        if (decryptionWSSCrypto == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "decryptionKeyStoreNotSet");
        }

        return decryptionWSSCrypto.getCrypto();
    }

    /**
     * Returns the encryption keystore
     *
     * @return A keystore for encryption operation
     */
    public KeyStore getEncryptionKeyStore() {
        if (encryptionWSSCrypto != null) {
            return encryptionWSSCrypto.getKeyStore();
        }
        return null;
    }

    /**
     * loads a java keystore from the given url for encrypt operations
     *
     * @param url              The URL to the keystore
     * @param keyStorePassword The keyStorePassword
     * @throws Exception thrown if something goes wrong while loading the keystore
     */
    public void loadEncryptionKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        if (encryptionWSSCrypto == null) {
            encryptionWSSCrypto = new WSSCrypto();
        }
        encryptionWSSCrypto.setKeyStore(keyStore);
    }

    public Properties getEncryptionCryptoProperties() {
        if (encryptionWSSCrypto != null) {
            return encryptionWSSCrypto.getCryptoProperties();
        }
        return null;
    }
    
    public void setEncryptionCryptoProperties(Properties cryptoProperties) {
        if (encryptionWSSCrypto == null) {
            encryptionWSSCrypto = new WSSCrypto();
        }
        encryptionWSSCrypto.setCryptoProperties(cryptoProperties);
    }

    /**
     * Returns the encryption crypto class
     *
     * @return
     */
    public Class<? extends Merlin> getEncryptionCryptoClass() {
        if (encryptionWSSCrypto != null) {
            return encryptionWSSCrypto.getCryptoClass();
        }
        return org.apache.wss4j.common.crypto.Merlin.class;
    }

    /**
     * Sets a custom encryption class
     *
     * @param encryptionCryptoClass
     */
    public void setEncryptionCryptoClass(Class<? extends Merlin> encryptionCryptoClass) {
        if (encryptionWSSCrypto == null) {
            encryptionWSSCrypto = new WSSCrypto();
        }
        encryptionWSSCrypto.setCryptoClass(encryptionCryptoClass);
    }

    /**
     * returns the encryptionCrypto for the key-management
     *
     * @return A Crypto instance
     * @throws WSSConfigurationException thrown if something goes wrong
     */
    public Crypto getEncryptionCrypto() throws WSSConfigurationException {

        if (encryptionWSSCrypto == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "encryptionKeyStoreNotSet");
        }

        encryptionWSSCrypto.setCrlCertStore(this.getCrlCertStore());
        return encryptionWSSCrypto.getCrypto();
    }
    
    /**
     * Returns the alias for the encryption key in the keystore
     *
     * @return the alias for the encryption key in the keystore as string
     */
    public String getEncryptionUser() {
        return encryptionUser;
    }

    /**
     * Specifies the the alias for the encryption key in the keystore
     *
     * @param encryptionUser the the alias for the encryption key in the keystore as string
     */
    public void setEncryptionUser(String encryptionUser) {
        this.encryptionUser = encryptionUser;
    }

    public String getEncryptionCompressionAlgorithm() {
        return encryptionCompressionAlgorithm;
    }

    public void setEncryptionCompressionAlgorithm(String encryptionCompressionAlgorithm) {
        this.encryptionCompressionAlgorithm = encryptionCompressionAlgorithm;
    }

    public boolean isAllowUsernameTokenNoPassword() {
        return allowUsernameTokenNoPassword;
    }

    public void setAllowUsernameTokenNoPassword(boolean allowUsernameTokenNoPassword) {
        this.allowUsernameTokenNoPassword = allowUsernameTokenNoPassword;
    }

    public boolean isEnableRevocation() {
        return enableRevocation;
    }

    public void setEnableRevocation(boolean enableRevocation) {
        this.enableRevocation = enableRevocation;
    }

    public CertStore getCrlCertStore() {
        return crlCertStore;
    }

    public void setCrlCertStore(CertStore crlCertStore) {
        this.crlCertStore = crlCertStore;
    }

    public Integer getTimeStampFutureTTL() {
        return timeStampFutureTTL;
    }

    public void setTimeStampFutureTTL(Integer timeStampFutureTTL) {
        this.timeStampFutureTTL = timeStampFutureTTL;
    }

    public Integer getUtTTL() {
        return utTTL;
    }

    public void setUtTTL(Integer utTTL) {
        this.utTTL = utTTL;
    }

    public Integer getUtFutureTTL() {
        return utFutureTTL;
    }

    public void setUtFutureTTL(Integer utFutureTTL) {
        this.utFutureTTL = utFutureTTL;
    }
    
    /**
     * Set the replay cache for Timestamps
     */
    public void setTimestampReplayCache(ReplayCache newCache) {
        timestampReplayCache = newCache;
    }

    /**
     * Get the replay cache for Timestamps
     * @throws WSSecurityException 
     */
    public ReplayCache getTimestampReplayCache() throws WSSecurityException {
        if (timestampReplayCache == null) {
            timestampReplayCache = createCache("wss4j-timestamp-cache-");
        }
        
        return timestampReplayCache;
    }
    
    private synchronized ReplayCache createCache(String key) throws WSSecurityException {
        ReplayCacheFactory replayCacheFactory = ReplayCacheFactory.newInstance();
        byte[] nonceValue = new byte[10];
        WSSConstants.secureRandom.nextBytes(nonceValue);
        String cacheKey = key + Base64.encode(nonceValue);
        return replayCacheFactory.newReplayCache(cacheKey, null);
    }
    
    /**
     * Set the replay cache for Nonces
     */
    public void setNonceReplayCache(ReplayCache newCache) {
        nonceReplayCache = newCache;
    }

    /**
     * Get the replay cache for Nonces
     * @throws WSSecurityException 
     */
    public ReplayCache getNonceReplayCache() throws WSSecurityException {
        if (nonceReplayCache == null) {
            nonceReplayCache = createCache("wss4j-nonce-cache-");
        }
        
        return nonceReplayCache;
    }

    public boolean isDisableBSPEnforcement() {
        return disableBSPEnforcement;
    }

    public void setDisableBSPEnforcement(boolean disableBSPEnforcement) {
        this.disableBSPEnforcement = disableBSPEnforcement;
    }
    
}
