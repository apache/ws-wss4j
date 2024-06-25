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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.FIPSUtils;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.validate.Validator;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;

/**
 * Main configuration class to supply keys etc.
 * This class is subject to change in the future.
 * Probably we will allow to configure the framework per WSDL
 */
public class WSSSecurityProperties extends XMLSecurityProperties {

    private boolean mustUnderstand = true;
    private String actor;
    private CallbackHandler callbackHandler;
    private CallbackHandler samlCallbackHandler;
    private final List<BSPRule> ignoredBSPRules = new LinkedList<>();
    private boolean disableBSPEnforcement;
    private final Map<QName, Validator> validators = new HashMap<>();

    private Integer timestampTTL = 300;
    private Integer timeStampFutureTTL = 60;
    private boolean strictTimestampCheck = true;
    private Integer utTTL = 300;
    private Integer utFutureTTL = 60;
    private Integer derivedKeyIterations = 1000;
    private boolean addUsernameTokenNonce;
    private boolean addUsernameTokenCreated;
    private boolean encryptSymmetricEncrytionKey = true;
    private boolean use200512Namespace = true;

    /**
     * This variable controls whether types other than PasswordDigest or PasswordText
     * are allowed when processing UsernameTokens.
     *
     * By default this is set to false so that the user doesn't have to explicitly
     * reject custom token types in the callback handler.
     */
    private boolean handleCustomPasswordTypes = false;
    private boolean allowUsernameTokenNoPassword = false;
    private boolean allowRSA15KeyTransportAlgorithm = FIPSUtils.isFIPSEnabled();
    private boolean useDerivedKeyForMAC = true;
    private WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType;
    private String tokenUser;

    private WSSecurityTokenConstants.KeyIdentifier derivedKeyKeyIdentifier;
    private WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference;
    private int derivedSignatureKeyLength;
    private int derivedEncryptionKeyLength;

    private WSSCrypto signatureWSSCrypto;
    private String signatureUser;
    private boolean enableSignatureConfirmationVerification = false;
    private boolean includeSignatureToken;
    private boolean includeEncryptionToken;
    private WSSCrypto signatureVerificationWSSCrypto;
    private CertStore crlCertStore;
    private WSSCrypto decryptionWSSCrypto;
    private WSSCrypto encryptionWSSCrypto;
    private String encryptionUser;
    private boolean useReqSigCertForEncryption = false;
    private String encryptionCompressionAlgorithm;
    private boolean enableRevocation = false;
    private ReplayCache timestampReplayCache;
    private ReplayCache nonceReplayCache;
    private ReplayCache samlOneTimeUseReplayCache;
    private boolean validateSamlSubjectConfirmation = true;
    private Collection<Pattern> subjectDNPatterns = new ArrayList<>();
    private Collection<Pattern> issuerDNPatterns = new ArrayList<>();
    private List<String> audienceRestrictions = new ArrayList<>();
    private boolean requireTimestampExpires;

    private CallbackHandler attachmentCallbackHandler;
    private Object msgContext;
    private boolean soap12;
    private DocumentCreator documentCreator;

    public WSSSecurityProperties() {
        super();
        setAddExcC14NInclusivePrefixes(true);
    }

    public WSSSecurityProperties(WSSSecurityProperties wssSecurityProperties) {
        super(wssSecurityProperties);

        this.mustUnderstand = wssSecurityProperties.mustUnderstand;
        this.actor = wssSecurityProperties.actor;
        this.callbackHandler = wssSecurityProperties.callbackHandler;
        this.samlCallbackHandler = wssSecurityProperties.samlCallbackHandler;
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
        this.use200512Namespace = wssSecurityProperties.use200512Namespace;
        this.derivedKeyKeyIdentifier = wssSecurityProperties.derivedKeyKeyIdentifier;
        this.derivedKeyTokenReference = wssSecurityProperties.derivedKeyTokenReference;
        this.derivedSignatureKeyLength = wssSecurityProperties.derivedSignatureKeyLength;
        this.derivedEncryptionKeyLength = wssSecurityProperties.derivedEncryptionKeyLength;
        this.signatureWSSCrypto = wssSecurityProperties.signatureWSSCrypto;
        this.signatureUser = wssSecurityProperties.signatureUser;
        this.enableSignatureConfirmationVerification = wssSecurityProperties.enableSignatureConfirmationVerification;
        this.includeSignatureToken = wssSecurityProperties.includeSignatureToken;
        this.includeEncryptionToken = wssSecurityProperties.includeEncryptionToken;
        this.signatureVerificationWSSCrypto = wssSecurityProperties.signatureVerificationWSSCrypto;
        this.crlCertStore = wssSecurityProperties.crlCertStore;
        this.decryptionWSSCrypto = wssSecurityProperties.decryptionWSSCrypto;
        this.encryptionWSSCrypto = wssSecurityProperties.encryptionWSSCrypto;
        this.encryptionUser = wssSecurityProperties.encryptionUser;
        this.useReqSigCertForEncryption = wssSecurityProperties.useReqSigCertForEncryption;
        this.encryptionCompressionAlgorithm = wssSecurityProperties.encryptionCompressionAlgorithm;
        this.enableRevocation = wssSecurityProperties.enableRevocation;
        this.timestampReplayCache = wssSecurityProperties.timestampReplayCache;
        this.nonceReplayCache = wssSecurityProperties.nonceReplayCache;
        this.samlOneTimeUseReplayCache = wssSecurityProperties.samlOneTimeUseReplayCache;
        this.allowRSA15KeyTransportAlgorithm = wssSecurityProperties.allowRSA15KeyTransportAlgorithm;
        this.derivedKeyIterations = wssSecurityProperties.derivedKeyIterations;
        this.useDerivedKeyForMAC = wssSecurityProperties.useDerivedKeyForMAC;
        this.addUsernameTokenNonce = wssSecurityProperties.addUsernameTokenNonce;
        this.addUsernameTokenCreated = wssSecurityProperties.addUsernameTokenCreated;
        this.validateSamlSubjectConfirmation = wssSecurityProperties.validateSamlSubjectConfirmation;
        this.encryptSymmetricEncrytionKey = wssSecurityProperties.encryptSymmetricEncrytionKey;
        this.subjectDNPatterns = wssSecurityProperties.subjectDNPatterns;
        this.issuerDNPatterns = wssSecurityProperties.issuerDNPatterns;
        this.attachmentCallbackHandler = wssSecurityProperties.attachmentCallbackHandler;
        this.msgContext = wssSecurityProperties.msgContext;
        this.audienceRestrictions = wssSecurityProperties.audienceRestrictions;
        this.requireTimestampExpires = wssSecurityProperties.requireTimestampExpires;
        this.soap12 = wssSecurityProperties.soap12;
        this.documentCreator = wssSecurityProperties.documentCreator;
    }

    /**
     * returns the password callback handler
     *
     * @return the password callback handler
     */
    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }


    /**
     * sets the password callback handler
     *
     * @param callbackHandler the password callback handler
     */
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
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
        return null;    //NOPMD
    }

    public void setSignatureCryptoProperties(Properties cryptoProperties) {
        this.setSignatureCryptoProperties(cryptoProperties, null);
    }

    public void setSignatureCryptoProperties(Properties cryptoProperties,
                                             PasswordEncryptor passwordEncryptor) {
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        signatureWSSCrypto.setCryptoProperties(cryptoProperties);
        signatureWSSCrypto.setPasswordEncryptor(passwordEncryptor);
    }

    public Class<? extends Merlin> getSignatureCryptoClass() {
        if (signatureWSSCrypto != null) {
            return signatureWSSCrypto.getCryptoClass();
        }
        return Merlin.class;
    }

    public void setSignatureCryptoClass(Class<? extends Merlin> signatureCryptoClass) {
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        this.signatureWSSCrypto.setCryptoClass(signatureCryptoClass);
    }

    public Crypto getSignatureCrypto() throws WSSConfigurationException {
        if (signatureWSSCrypto == null) {
            return null;
        }

        return signatureWSSCrypto.getCrypto();
    }

    public void setSignatureCrypto(Crypto sigCrypto) {
        if (signatureWSSCrypto == null) {
            signatureWSSCrypto = new WSSCrypto();
        }
        signatureWSSCrypto.setCrypto(sigCrypto);
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
        return null;    //NOPMD
    }

    public void setSignatureVerificationCryptoProperties(Properties cryptoProperties) {
        this.setSignatureVerificationCryptoProperties(cryptoProperties, null);
    }

    public void setSignatureVerificationCryptoProperties(Properties cryptoProperties,
                                                         PasswordEncryptor passwordEncryptor) {
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        signatureVerificationWSSCrypto.setCryptoProperties(cryptoProperties);
        signatureVerificationWSSCrypto.setPasswordEncryptor(passwordEncryptor);
    }

    public Class<? extends Merlin> getSignatureVerificationCryptoClass() {
        if (signatureVerificationWSSCrypto != null) {
            return signatureVerificationWSSCrypto.getCryptoClass();
        }
        return Merlin.class;
    }

    public void setSignatureVerificationCryptoClass(Class<? extends Merlin> signatureVerificationCryptoClass) {
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        this.signatureVerificationWSSCrypto.setCryptoClass(signatureVerificationCryptoClass);

    }

    public Crypto getSignatureVerificationCrypto() throws WSSConfigurationException {

        if (signatureVerificationWSSCrypto == null) {
            return null;
        }
        signatureVerificationWSSCrypto.setCrlCertStore(crlCertStore);
        return signatureVerificationWSSCrypto.getCrypto();
    }

    public void setSignatureVerificationCrypto(Crypto sigVerCrypto) {
        if (signatureVerificationWSSCrypto == null) {
            signatureVerificationWSSCrypto = new WSSCrypto();
        }
        signatureVerificationWSSCrypto.setCrypto(sigVerCrypto);
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
        return null;    //NOPMD
    }

    public void setDecryptionCryptoProperties(Properties cryptoProperties) {
        this.setDecryptionCryptoProperties(cryptoProperties, null);
    }

    public void setDecryptionCryptoProperties(Properties cryptoProperties,
                                              PasswordEncryptor passwordEncryptor) {
        if (decryptionWSSCrypto == null) {
            decryptionWSSCrypto = new WSSCrypto();
        }
        decryptionWSSCrypto.setCryptoProperties(cryptoProperties);
        decryptionWSSCrypto.setPasswordEncryptor(passwordEncryptor);
    }

    /**
     * Returns the decryption crypto class
     *
     * @return the decryption crypto class
     */
    public Class<? extends Merlin> getDecryptionCryptoClass() {
        if (decryptionWSSCrypto != null) {
            return decryptionWSSCrypto.getCryptoClass();
        }
        return Merlin.class;
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
            return null;
        }

        return decryptionWSSCrypto.getCrypto();
    }

    public void setDecryptionCrypto(Crypto decCrypto) {
        if (decryptionWSSCrypto == null) {
            decryptionWSSCrypto = new WSSCrypto();
        }
        decryptionWSSCrypto.setCrypto(decCrypto);
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
        return null;    //NOPMD
    }

    public void setEncryptionCryptoProperties(Properties cryptoProperties) {
        this.setEncryptionCryptoProperties(cryptoProperties, null);
    }

    public void setEncryptionCryptoProperties(Properties cryptoProperties,
                                              PasswordEncryptor passwordEncryptor) {
        if (encryptionWSSCrypto == null) {
            encryptionWSSCrypto = new WSSCrypto();
        }
        encryptionWSSCrypto.setCryptoProperties(cryptoProperties);
        encryptionWSSCrypto.setPasswordEncryptor(passwordEncryptor);
    }

    /**
     * Returns the encryption crypto class
     *
     * @return the encryption crypto class
     */
    public Class<? extends Merlin> getEncryptionCryptoClass() {
        if (encryptionWSSCrypto != null) {
            return encryptionWSSCrypto.getCryptoClass();
        }
        return Merlin.class;
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
            return null;
        }

        encryptionWSSCrypto.setCrlCertStore(this.getCrlCertStore());
        return encryptionWSSCrypto.getCrypto();
    }

    public void setEncryptionCrypto(Crypto encCrypto) {
        if (encryptionWSSCrypto == null) {
            encryptionWSSCrypto = new WSSCrypto();
        }
        encryptionWSSCrypto.setCrypto(encCrypto);
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
        return timestampReplayCache;
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
        return nonceReplayCache;
    }

    /**
     * Set the replay cache for SAML2 OneTimeUse Assertions
     */
    public void setSamlOneTimeUseReplayCache(ReplayCache newCache) {
        samlOneTimeUseReplayCache = newCache;
    }

    /**
     * Get the replay cache for SAML2 OneTimeUse Assertions
     * @throws WSSecurityException
     */
    public ReplayCache getSamlOneTimeUseReplayCache() throws WSSecurityException {
        return samlOneTimeUseReplayCache;
    }

    public boolean isDisableBSPEnforcement() {
        return disableBSPEnforcement;
    }

    public void setDisableBSPEnforcement(boolean disableBSPEnforcement) {
        this.disableBSPEnforcement = disableBSPEnforcement;
    }

    public boolean isAllowRSA15KeyTransportAlgorithm() {
        return allowRSA15KeyTransportAlgorithm;
    }

    public void setAllowRSA15KeyTransportAlgorithm(boolean allowRSA15KeyTransportAlgorithm) {
        this.allowRSA15KeyTransportAlgorithm = allowRSA15KeyTransportAlgorithm;
    }

    public Integer getDerivedKeyIterations() {
        return derivedKeyIterations;
    }

    public void setDerivedKeyIterations(Integer derivedKeyIterations) {
        this.derivedKeyIterations = derivedKeyIterations;
    }

    public boolean isUseDerivedKeyForMAC() {
        return useDerivedKeyForMAC;
    }

    public void setUseDerivedKeyForMAC(boolean useDerivedKeyForMAC) {
        this.useDerivedKeyForMAC = useDerivedKeyForMAC;
    }

    public boolean isAddUsernameTokenNonce() {
        return addUsernameTokenNonce;
    }

    public void setAddUsernameTokenNonce(boolean addUsernameTokenNonce) {
        this.addUsernameTokenNonce = addUsernameTokenNonce;
    }

    public boolean isAddUsernameTokenCreated() {
        return addUsernameTokenCreated;
    }

    public void setAddUsernameTokenCreated(boolean addUsernameTokenCreated) {
        this.addUsernameTokenCreated = addUsernameTokenCreated;
    }

    public CallbackHandler getSamlCallbackHandler() {
        return samlCallbackHandler;
    }

    public void setSamlCallbackHandler(CallbackHandler samlCallbackHandler) {
        this.samlCallbackHandler = samlCallbackHandler;
    }

    public boolean isValidateSamlSubjectConfirmation() {
        return validateSamlSubjectConfirmation;
    }

    public void setValidateSamlSubjectConfirmation(boolean validateSamlSubjectConfirmation) {
        this.validateSamlSubjectConfirmation = validateSamlSubjectConfirmation;
    }

    public boolean isMustUnderstand() {
        return mustUnderstand;
    }

    public void setMustUnderstand(boolean mustUnderstand) {
        this.mustUnderstand = mustUnderstand;
    }

    public boolean isIncludeSignatureToken() {
        return includeSignatureToken;
    }

    public void setIncludeSignatureToken(boolean includeSignatureToken) {
        this.includeSignatureToken = includeSignatureToken;
    }

    public boolean isIncludeEncryptionToken() {
        return includeEncryptionToken;
    }

    public void setIncludeEncryptionToken(boolean includeEncryptionToken) {
        this.includeEncryptionToken = includeEncryptionToken;
    }

    public boolean isEncryptSymmetricEncryptionKey() {
        return encryptSymmetricEncrytionKey;
    }

    public void setEncryptSymmetricEncryptionKey(boolean encryptSymmetricEncrytionKey) {
        this.encryptSymmetricEncrytionKey = encryptSymmetricEncrytionKey;
    }

    /**
     * Set the Signature Subject Cert Constraints
     */
    public void setSubjectCertConstraints(Collection<Pattern> subjectCertConstraints) {
        if (subjectCertConstraints != null) {
            subjectDNPatterns.addAll(subjectCertConstraints);
        }
    }

    /**
     * Get the Signature Subject Cert Constraints
     */
    public Collection<Pattern> getSubjectCertConstraints() {
        return subjectDNPatterns;
    }
    /**
     * Set the Signature Issuer Cert Constraints
     */
    public void setIssuerDNConstraints(Collection<Pattern> issuerDNPatterns) {
        this.issuerDNPatterns = issuerDNPatterns;
    }
    /**
     * Get the Signature Issuer Cert Constraints
     */
    public Collection<Pattern> getIssuerDNConstraints() {
        return issuerDNPatterns;
    }



    /**
     * Set the Audience Restrictions
     */
    public void setAudienceRestrictions(List<String> audienceRestrictions) {
        if (audienceRestrictions != null) {
            this.audienceRestrictions.addAll(audienceRestrictions);
        }
    }

    /**
     * Get the Audience Restrictions
     */
    public List<String> getAudienceRestrictions() {
        return audienceRestrictions;
    }

    public int getDerivedSignatureKeyLength() {
        return derivedSignatureKeyLength;
    }

    public void setDerivedSignatureKeyLength(int derivedSignatureKeyLength) {
        this.derivedSignatureKeyLength = derivedSignatureKeyLength;
    }

    public int getDerivedEncryptionKeyLength() {
        return derivedEncryptionKeyLength;
    }

    public void setDerivedEncryptionKeyLength(int derivedEncryptionKeyLength) {
        this.derivedEncryptionKeyLength = derivedEncryptionKeyLength;
    }

    public boolean isUse200512Namespace() {
        return use200512Namespace;
    }

    public void setUse200512Namespace(boolean use200512Namespace) {
        this.use200512Namespace = use200512Namespace;
    }

    public CallbackHandler getAttachmentCallbackHandler() {
        return attachmentCallbackHandler;
    }

    public void setAttachmentCallbackHandler(CallbackHandler attachmentCallbackHandler) {
        this.attachmentCallbackHandler = attachmentCallbackHandler;
    }

    public Object getMsgContext() {
        return msgContext;
    }

    public void setMsgContext(Object msgContext) {
        this.msgContext = msgContext;
    }

    public boolean isRequireTimestampExpires() {
        return requireTimestampExpires;
    }

    public void setRequireTimestampExpires(boolean requireTimestampExpires) {
        this.requireTimestampExpires = requireTimestampExpires;
    }

    public boolean isSoap12() {
        return soap12;
    }

    public void setSoap12(boolean soap12) {
        this.soap12 = soap12;
    }

    public DocumentCreator getDocumentCreator() {
        return documentCreator;
    }

    public void setDocumentCreator(DocumentCreator documentCreator) {
        this.documentCreator = documentCreator;
    }
}
