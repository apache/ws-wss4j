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

package org.apache.wss4j.dom.handler;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.EncryptionActionToken;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.cache.ReplayCacheFactory;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.bsp.BSPEnforcer;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.Validator;
import org.apache.xml.security.utils.Base64;

/**
 * This class holds per request data.
 */
public class RequestData {
    
    private Object msgContext;
    private SOAPConstants soapConstants ;
    private String actor;
    private String username ;
    private String pwType = WSConstants.PASSWORD_DIGEST; // Make this the default when no password type is given.
    private Crypto sigVerCrypto;
    private Crypto decCrypto;
    private SignatureActionToken signatureToken;
    private EncryptionActionToken encryptionToken;
    private int timeToLive = 300;   // Timestamp: time in seconds between creation and expiry
    private WSSConfig wssConfig;
    private List<byte[]> signatureValues = new ArrayList<byte[]>();
    private WSSecHeader secHeader;
    private int derivedKeyIterations = UsernameToken.DEFAULT_ITERATION;
    private boolean useDerivedKeyForMAC = true;
    private CallbackHandler callback;
    private boolean enableRevocation;
    protected boolean requireSignedEncryptedDataElements;
    private ReplayCache timestampReplayCache;
    private ReplayCache nonceReplayCache;
    private ReplayCache samlOneTimeUseReplayCache;
    private Collection<Pattern> subjectDNPatterns = new ArrayList<Pattern>();
    private final List<BSPRule> ignoredBSPRules = new LinkedList<BSPRule>();
    private boolean appendSignatureAfterTimestamp;
    private int originalSignatureActionPosition;
    private AlgorithmSuite algorithmSuite;
    private AlgorithmSuite samlAlgorithmSuite;
    private boolean disableBSPEnforcement;
    private boolean allowRSA15KeyTransportAlgorithm;
    private boolean addUsernameTokenNonce;
    private boolean addUsernameTokenCreated;
    private Certificate[] tlsCerts;
    private boolean enableTimestampReplayCache = true;
    private boolean enableNonceReplayCache = true;
    private boolean enableSamlOneTimeUseReplayCache = true;
    private PasswordEncryptor passwordEncryptor;

    public void clear() {
        soapConstants = null;
        actor = username = pwType = null;
        decCrypto = sigVerCrypto = null;
        signatureToken = null;
        encryptionToken = null;
        wssConfig = null;
        signatureValues.clear();
        derivedKeyIterations = UsernameToken.DEFAULT_ITERATION;
        useDerivedKeyForMAC = true;
        callback = null;
        enableRevocation = false;
        timestampReplayCache = null;
        nonceReplayCache = null;
        samlOneTimeUseReplayCache = null;
        subjectDNPatterns.clear();
        ignoredBSPRules.clear();
        appendSignatureAfterTimestamp = false;
        algorithmSuite = null;
        samlAlgorithmSuite = null;
        setOriginalSignatureActionPosition(0);
        setDisableBSPEnforcement(false);
        allowRSA15KeyTransportAlgorithm = false;
        setAddUsernameTokenNonce(false);
        setAddUsernameTokenCreated(false);
        setTlsCerts(null);
        enableTimestampReplayCache = true;
        enableNonceReplayCache = true;
        setEnableSamlOneTimeUseReplayCache(true);
        passwordEncryptor = null;
    }

    public boolean isEnableTimestampReplayCache() {
        return enableTimestampReplayCache;
    }

    public void setEnableTimestampReplayCache(boolean enableTimestampReplayCache) {
        this.enableTimestampReplayCache = enableTimestampReplayCache;
    }

    public boolean isEnableNonceReplayCache() {
        return enableNonceReplayCache;
    }

    public void setEnableNonceReplayCache(boolean enableNonceReplayCache) {
        this.enableNonceReplayCache = enableNonceReplayCache;
    }

    public Object getMsgContext() {
        return msgContext;
    }

    public void setMsgContext(Object msgContext) {
        this.msgContext = msgContext;
    }

    public SOAPConstants getSoapConstants() {
        return soapConstants;
    }

    public void setSoapConstants(SOAPConstants soapConstants) {
        this.soapConstants = soapConstants;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }
    
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPwType() {
        return pwType;
    }

    public void setPwType(String pwType) {
        this.pwType = pwType;
    }

    public Crypto getSigVerCrypto() {
        return sigVerCrypto;
    }

    public void setSigVerCrypto(Crypto sigVerCrypto) {
        this.sigVerCrypto = sigVerCrypto;
    }

    public Crypto getDecCrypto() {
        return decCrypto;
    }

    public void setDecCrypto(Crypto decCrypto) {
        this.decCrypto = decCrypto;
    }

    public int getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(int timeToLive) {
        this.timeToLive = timeToLive;
    }

    /**
     * @return Returns the wssConfig.
     */
    public WSSConfig getWssConfig() {
        return wssConfig;
    }

    /**
     * @param wssConfig The wssConfig to set.
     */
    public void setWssConfig(WSSConfig wssConfig) {
        this.wssConfig = wssConfig;
    }
    
    /**
     * @return Returns the list of stored signature values.
     */
    public List<byte[]> getSignatureValues() {
        return signatureValues;
    }

    /**
     * @return Returns the secHeader.
     */
    public WSSecHeader getSecHeader() {
        return secHeader;
    }

    /**
     * @param secHeader The secHeader to set.
     */
    public void setSecHeader(WSSecHeader secHeader) {
        this.secHeader = secHeader;
    }
    
    /**
     * Set the derived key iterations. Default is 1000.
     * @param iterations The number of iterations to use when deriving a key
     */
    public void setDerivedKeyIterations(int iterations) {
        derivedKeyIterations = iterations;
    }
    
    /**
     * Get the derived key iterations.
     * @return The number of iterations to use when deriving a key
     */
    public int getDerivedKeyIterations() {
        return derivedKeyIterations;
    }
    
    /**
     * Whether to use the derived key for a MAC.
     * @param useMac Whether to use the derived key for a MAC.
     */
    public void setUseDerivedKeyForMAC(boolean useMac) {
        useDerivedKeyForMAC = useMac;
    }
    
    /**
     * Whether to use the derived key for a MAC.
     * @return Whether to use the derived key for a MAC.
     */
    public boolean isUseDerivedKeyForMAC() {
        return useDerivedKeyForMAC;
    }
    
    /**
     * Set whether to enable CRL checking or not when verifying trust in a certificate.
     * @param enableRevocation whether to enable CRL checking 
     */
    public void setEnableRevocation(boolean enableRevocation) {
        this.enableRevocation = enableRevocation;
    }
    
    /**
     * Get whether to enable CRL checking or not when verifying trust in a certificate.
     * @return whether to enable CRL checking
     */
    public boolean isRevocationEnabled() {
        return enableRevocation;
    }
    
    /**
     * @return whether EncryptedData elements are required to be signed
     */
    public boolean isRequireSignedEncryptedDataElements() {
        return requireSignedEncryptedDataElements;
    }

    /**
     * Configure the engine to verify that EncryptedData elements
     * are in a signed subtree of the document. This can be used to
     * prevent some wrapping based attacks when encrypt-before-sign
     * token protection is selected.
     *  
     * @param requireSignedEncryptedDataElements
     */
    public void setRequireSignedEncryptedDataElements(boolean requireSignedEncryptedDataElements) {
        this.requireSignedEncryptedDataElements = requireSignedEncryptedDataElements;
    }
    
    /**
     * Sets the CallbackHandler used for this request
     * @param cb
     */
    public void setCallbackHandler(CallbackHandler cb) { 
        callback = cb;
    }
    
    /**
     * Returns the CallbackHandler used for this request.
     * @return the CallbackHandler used for this request.
     */
    public CallbackHandler getCallbackHandler() {
        return callback;
    }

    /**
     * Get the Validator instance corresponding to the QName
     * @param qName the QName with which to find a Validator instance
     * @return the Validator instance corresponding to the QName
     * @throws WSSecurityException
     */
    public Validator getValidator(QName qName) throws WSSecurityException {
        if (wssConfig != null)  {
            return wssConfig.getValidator(qName);
        }
        return null;
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
        if (enableTimestampReplayCache && timestampReplayCache == null) {
            timestampReplayCache = createCache("wss4j-timestamp-cache-");
        }
        
        return timestampReplayCache;
    }
    
    private synchronized ReplayCache createCache(String key) throws WSSecurityException {
        ReplayCacheFactory replayCacheFactory = ReplayCacheFactory.newInstance();
        String cacheKey = key + Base64.encode(WSSecurityUtil.generateNonce(10));
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
        if (enableNonceReplayCache && nonceReplayCache == null) {
            nonceReplayCache = createCache("wss4j-nonce-cache-");
        }
        
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
        if (enableSamlOneTimeUseReplayCache && samlOneTimeUseReplayCache == null) {
            samlOneTimeUseReplayCache = createCache("wss4j-saml-one-time-use-cache-");
        }
        
        return samlOneTimeUseReplayCache;
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
    
    public void setIgnoredBSPRules(List<BSPRule> bspRules) {
        ignoredBSPRules.clear();
        ignoredBSPRules.addAll(bspRules);
    }

    public List<BSPRule> getIgnoredBSPRules() {
        return Collections.unmodifiableList(ignoredBSPRules);
    }
    
    public BSPEnforcer getBSPEnforcer() {
        if (disableBSPEnforcement) {
            return new BSPEnforcer(true);
        }
        return new BSPEnforcer(ignoredBSPRules);
    }

    public boolean isAppendSignatureAfterTimestamp() {
        return appendSignatureAfterTimestamp;
    }

    public void setAppendSignatureAfterTimestamp(boolean appendSignatureAfterTimestamp) {
        this.appendSignatureAfterTimestamp = appendSignatureAfterTimestamp;
    }

    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    public void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }
    
    public AlgorithmSuite getSamlAlgorithmSuite() {
        return samlAlgorithmSuite;
    }

    public void setSamlAlgorithmSuite(AlgorithmSuite samlAlgorithmSuite) {
        this.samlAlgorithmSuite = samlAlgorithmSuite;
    }

    public int getOriginalSignatureActionPosition() {
        return originalSignatureActionPosition;
    }

    public void setOriginalSignatureActionPosition(int originalSignatureActionPosition) {
        this.originalSignatureActionPosition = originalSignatureActionPosition;
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

    public Certificate[] getTlsCerts() {
        return tlsCerts;
    }

    public void setTlsCerts(Certificate[] tlsCerts) {
        this.tlsCerts = tlsCerts;
    }

    public PasswordEncryptor getPasswordEncryptor() {
        return passwordEncryptor;
    }

    public void setPasswordEncryptor(PasswordEncryptor passwordEncryptor) {
        this.passwordEncryptor = passwordEncryptor;
    }

    public boolean isEnableSamlOneTimeUseReplayCache() {
        return enableSamlOneTimeUseReplayCache;
    }

    public void setEnableSamlOneTimeUseReplayCache(boolean enableSamlOneTimeUseReplayCache) {
        this.enableSamlOneTimeUseReplayCache = enableSamlOneTimeUseReplayCache;
    }

    public SignatureActionToken getSignatureToken() {
        return signatureToken;
    }

    public void setSignatureToken(SignatureActionToken signatureToken) {
        this.signatureToken = signatureToken;
    }

    public EncryptionActionToken getEncryptionToken() {
        return encryptionToken;
    }

    public void setEncryptionToken(EncryptionActionToken encryptionToken) {
        this.encryptionToken = encryptionToken;
    }
        
}
