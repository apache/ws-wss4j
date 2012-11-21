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

package org.apache.ws.security.handler;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.cache.ReplayCache;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Validator;

/**
 * This class holds per request data.
 *
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class RequestData {
    
    private Object msgContext = null;
    private boolean noSerialization = false;
    private SOAPConstants soapConstants = null;
    private String actor = null;
    private String username = null;
    private String pwType = WSConstants.PASSWORD_DIGEST; // Make this the default when no password type is given.
    private String[] utElements = null;
    private Crypto sigCrypto = null;
    private Crypto decCrypto = null;
    private int sigKeyId = 0;
    private String sigAlgorithm = null;
    private String signatureDigestAlgorithm = null;
    private String encryptionDigestAlgorithm = null;
    private List<WSEncryptionPart> signatureParts = new ArrayList<WSEncryptionPart>();
    private Crypto encCrypto = null;
    private int encKeyId = 0;
    private String encSymmAlgo = null;
    private String encKeyTransport = null;
    private String encUser = null;
    private String signatureUser = null;
    private List<WSEncryptionPart> encryptParts = new ArrayList<WSEncryptionPart>();
    private X509Certificate encCert = null;
    private int timeToLive = 300;   // Timestamp: time in seconds between creation and expiry
    private WSSConfig wssConfig = null;
    private List<byte[]> signatureValues = new ArrayList<byte[]>();
    private WSSecHeader secHeader = null;
    private boolean encSymmetricEncryptionKey = true;
    private int secretKeyLength = WSConstants.WSE_DERIVED_KEY_LEN;
    private boolean useDerivedKey = true;
    private int derivedKeyIterations = UsernameToken.DEFAULT_ITERATION;
    private boolean useDerivedKeyForMAC = true;
    private boolean useSingleCert = true;
    private CallbackHandler callback = null;
    private boolean enableRevocation = false;
    protected boolean requireSignedEncryptedDataElements = false;
    private ReplayCache timestampReplayCache;
    private ReplayCache nonceReplayCache;
    private Collection<Pattern> subjectDNPatterns = new ArrayList<Pattern>();
    private boolean appendSignatureAfterTimestamp;
    private AlgorithmSuite algorithmSuite;
    private AlgorithmSuite samlAlgorithmSuite;

    public void clear() {
        soapConstants = null;
        actor = username = pwType = sigAlgorithm = encSymmAlgo = encKeyTransport = encUser = null;
        sigCrypto = decCrypto = encCrypto = null;
        signatureParts.clear();
        encryptParts.clear();
        encCert = null;
        utElements = null;
        wssConfig = null;
        signatureValues.clear();
        signatureDigestAlgorithm = null;
        encryptionDigestAlgorithm = null;
        encSymmetricEncryptionKey = true;
        secretKeyLength = WSConstants.WSE_DERIVED_KEY_LEN;
        signatureUser = null;
        useDerivedKey = true;
        derivedKeyIterations = UsernameToken.DEFAULT_ITERATION;
        useDerivedKeyForMAC = true;
        useSingleCert = true;
        callback = null;
        enableRevocation = false;
        timestampReplayCache = null;
        nonceReplayCache = null;
        subjectDNPatterns.clear();
        appendSignatureAfterTimestamp = false;
        algorithmSuite = null;
        samlAlgorithmSuite = null;
    }

    public Object getMsgContext() {
        return msgContext;
    }

    public void setMsgContext(Object msgContext) {
        this.msgContext = msgContext;
    }

    public boolean isNoSerialization() {
        return noSerialization;
    }

    public void setNoSerialization(boolean noSerialization) {
        this.noSerialization = noSerialization;
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
    
    public void setSecretKeyLength(int length) {
        secretKeyLength = length;
    }
    
    public int getSecretKeyLength() {
        return secretKeyLength;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
    
    public void setEncryptSymmetricEncryptionKey(boolean encrypt) {
        encSymmetricEncryptionKey = encrypt;
    }
    
    public boolean getEncryptSymmetricEncryptionKey() {
        return encSymmetricEncryptionKey;
    }

    public String getPwType() {
        return pwType;
    }

    public void setPwType(String pwType) {
        this.pwType = pwType;
    }

    public String[] getUtElements() {
        return utElements;
    }

    public void setUtElements(String[] utElements) {
        this.utElements = utElements;
    }

    public Crypto getSigCrypto() {
        return sigCrypto;
    }

    public void setSigCrypto(Crypto sigCrypto) {
        this.sigCrypto = sigCrypto;
    }

    public Crypto getDecCrypto() {
        return decCrypto;
    }

    public void setDecCrypto(Crypto decCrypto) {
        this.decCrypto = decCrypto;
    }

    public int getSigKeyId() {
        return sigKeyId;
    }

    public void setSigKeyId(int sigKeyId) {
        this.sigKeyId = sigKeyId;
    }

    public String getSigAlgorithm() {
        return sigAlgorithm;
    }

    public void setSigAlgorithm(String sigAlgorithm) {
        this.sigAlgorithm = sigAlgorithm;
    }
    
    public String getSigDigestAlgorithm() {
        return signatureDigestAlgorithm;
    }

    public void setSigDigestAlgorithm(String sigDigestAlgorithm) {
        this.signatureDigestAlgorithm = sigDigestAlgorithm;
    }
    
    public String getEncDigestAlgorithm() {
        return encryptionDigestAlgorithm;
    }

    public void setEncDigestAlgorithm(String encDigestAlgorithm) {
        this.encryptionDigestAlgorithm = encDigestAlgorithm;
    }

    public List<WSEncryptionPart> getSignatureParts() {
        return signatureParts;
    }
    
    public String getSignatureUser() {
        return signatureUser;
    }

    public void setSignatureUser(String signatureUser) {
        this.signatureUser = signatureUser;
    }

    public Crypto getEncCrypto() {
        return encCrypto;
    }

    public void setEncCrypto(Crypto encCrypto) {
        this.encCrypto = encCrypto;
    }

    public int getEncKeyId() {
        return encKeyId;
    }

    public void setEncKeyId(int encKeyId) {
        this.encKeyId = encKeyId;
    }

    public String getEncSymmAlgo() {
        return encSymmAlgo;
    }

    public void setEncSymmAlgo(String encSymmAlgo) {
        this.encSymmAlgo = encSymmAlgo;
    }

    public String getEncKeyTransport() {
        return encKeyTransport;
    }

    public void setEncKeyTransport(String encKeyTransport) {
        this.encKeyTransport = encKeyTransport;
    }

    public String getEncUser() {
        return encUser;
    }

    public void setEncUser(String encUser) {
        this.encUser = encUser;
    }

    public List<WSEncryptionPart> getEncryptParts() {
        return encryptParts;
    }

    public X509Certificate getEncCert() {
        return encCert;
    }

    public void setEncCert(X509Certificate encCert) {
        this.encCert = encCert;
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
     * @param derivedKey Set whether to derive keys as per the 
     *        UsernameTokenProfile 1.1 spec. Default is true.
     */
    public void setUseDerivedKey(boolean derivedKey) {
        useDerivedKey = derivedKey;
    }
    
    /**
     * Return whether to derive keys as per the UsernameTokenProfile 
     * 1.1 spec. Default is true.
     */
    public boolean isUseDerivedKey() {
        return useDerivedKey;
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
     * Whether to use a single certificate or a whole certificate chain when
     * constructing a BinarySecurityToken used for direct reference in Signature.
     * @param useSingleCert true if only to use a single certificate
     */
    public void setUseSingleCert(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }
    
    /**
     * Whether to use a single certificate or a whole certificate chain when
     * constructing a BinarySecurityToken used for direct reference in Signature.
     * @return whether to use a single certificate
     */
    public boolean isUseSingleCert() {
        return useSingleCert;
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
     */
    public ReplayCache getTimestampReplayCache() {
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
     */
    public ReplayCache getNonceReplayCache() {
        return nonceReplayCache;
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
        
}
