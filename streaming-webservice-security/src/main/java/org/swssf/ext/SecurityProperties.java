/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import org.swssf.crypto.Crypto;
import org.swssf.crypto.CryptoBase;

import javax.security.auth.callback.CallbackHandler;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

/**
 * Main configuration class to supply keys etc.
 * This class is subject to change in the future.
 * Probably we will allow to configure the framework per WSDL
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityProperties {

    private List<InputProcessor> inputProcessorList = new LinkedList<InputProcessor>();

    /**
     * Add an additional, non standard, InputProcessor to the chain
     *
     * @param inputProcessor The InputProcessor to add
     */
    public void addInputProcessor(InputProcessor inputProcessor) {
        this.inputProcessorList.add(inputProcessor);
    }

    /**
     * Returns the currently registered additional InputProcessors
     *
     * @return the List with the InputProcessors
     */
    public List<InputProcessor> getInputProcessorList() {
        return inputProcessorList;
    }

    private Class decryptionCryptoClass;
    private KeyStore decryptionKeyStore;
    private CallbackHandler callbackHandler;

    /**
     * Returns the decryption keystore
     *
     * @return A keystore for decryption operation
     */
    public KeyStore getDecryptionKeyStore() {
        return decryptionKeyStore;
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
        this.decryptionKeyStore = keyStore;
    }

    /**
     * Returns the decryption crypto class
     *
     * @return
     */
    public Class getDecryptionCryptoClass() {
        return decryptionCryptoClass;
    }

    /**
     * Sets a custom decryption class
     *
     * @param decryptionCryptoClass
     */
    public void setDecryptionCryptoClass(Class decryptionCryptoClass) {
        this.decryptionCryptoClass = decryptionCryptoClass;
    }

    private Crypto cachedDecryptionCrypto;
    private Class cachedDecryptionCryptoClass;
    private KeyStore cachedDecryptionKeyStore;

    /**
     * returns the decryptionCrypto for the key-management
     *
     * @return A Crypto instance
     * @throws WSSecurityException thrown if something goes wrong
     */
    public Crypto getDecryptionCrypto() throws WSSecurityException {

        if (this.getDecryptionKeyStore() == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "decryptionKeyStoreNotSet");
        }

        if (this.getDecryptionCryptoClass() == cachedDecryptionCryptoClass
                && this.getDecryptionKeyStore() == cachedDecryptionKeyStore) {
            return cachedDecryptionCrypto;
        }

        Class decryptionCryptoClass = org.swssf.crypto.Merlin.class;
        if (this.getDecryptionCryptoClass() != null) {
            decryptionCryptoClass = this.getDecryptionCryptoClass();
            if (!decryptionCryptoClass.isAssignableFrom(CryptoBase.class)) {
                throw new WSSConfigurationException(WSSecurityException.FAILURE, "decryptionCryptoClassWrong");
            }
        }

        try {
            CryptoBase decryptionCrypto = (CryptoBase) decryptionCryptoClass.newInstance();
            decryptionCrypto.setKeyStore(this.getDecryptionKeyStore());
            cachedDecryptionCrypto = decryptionCrypto;
            cachedDecryptionCryptoClass = decryptionCryptoClass;
            cachedDecryptionKeyStore = this.getDecryptionKeyStore();
            return decryptionCrypto;
        } catch (Exception e) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "decryptionCryptoFailure", e);
        }
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

    private Constants.Action[] outAction;

    private Class encryptionCryptoClass;
    private KeyStore encryptionKeyStore;
    private String encryptionUser;
    private X509Certificate encryptionUseThisCertificate;
    private Constants.KeyIdentifierType encryptionKeyIdentifierType;
    private String encryptionSymAlgorithm;
    private String encryptionKeyTransportAlgorithm;
    private List<SecurePart> encryptionParts = new LinkedList<SecurePart>();

    /**
     * Returns the encryption keystore
     *
     * @return A keystore for encryption operation
     */
    public KeyStore getEncryptionKeyStore() {
        return encryptionKeyStore;
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
        this.encryptionKeyStore = keyStore;
    }

    /**
     * Returns the encryption crypto class
     *
     * @return
     */
    public Class getEncryptionCryptoClass() {
        return encryptionCryptoClass;
    }

    /**
     * Sets a custom encryption class
     *
     * @param encryptionCryptoClass
     */
    public void setEncryptionCryptoClass(Class encryptionCryptoClass) {
        this.encryptionCryptoClass = encryptionCryptoClass;
    }

    private Crypto cachedEncryptionCrypto;
    private Class cachedEncryptionCryptoClass;
    private KeyStore cachedEncryptionKeyStore;

    /**
     * returns the encryptionCrypto for the key-management
     *
     * @return A Crypto instance
     * @throws WSSecurityException thrown if something goes wrong
     */
    public Crypto getEncryptionCrypto() throws WSSecurityException {

        if (this.getEncryptionKeyStore() == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "encryptionKeyStoreNotSet");
        }

        if (this.getEncryptionCryptoClass() == cachedEncryptionCryptoClass
                && this.getEncryptionKeyStore() == cachedEncryptionKeyStore) {
            return cachedEncryptionCrypto;
        }

        Class encryptionCryptoClass = org.swssf.crypto.Merlin.class;
        if (this.getEncryptionCryptoClass() != null) {
            encryptionCryptoClass = this.getEncryptionCryptoClass();
            if (!CryptoBase.class.isAssignableFrom(encryptionCryptoClass)) {
                throw new WSSConfigurationException(WSSecurityException.FAILURE, "encryptionCryptoClassWrong");
            }
        }

        try {
            CryptoBase encryptionCrypto = (CryptoBase) encryptionCryptoClass.newInstance();
            encryptionCrypto.setKeyStore(this.getEncryptionKeyStore());
            cachedEncryptionCrypto = encryptionCrypto;
            cachedEncryptionCryptoClass = encryptionCryptoClass;
            cachedEncryptionKeyStore = this.getEncryptionKeyStore();
            return encryptionCrypto;
        } catch (Exception e) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "encryptionCryptoFailure", e);
        }
    }

    /**
     * Adds a part which must be encrypted by the framework
     *
     * @param securePart
     */
    public void addEncryptionPart(SecurePart securePart) {
        encryptionParts.add(securePart);
    }

    /**
     * Returns the encryption parts which are actually set
     *
     * @return A List of SecurePart's
     */
    public List<SecurePart> getEncryptionSecureParts() {
        return encryptionParts;
    }

    /**
     * Returns the Encryption-Algo
     *
     * @return the Encryption-Algo as String
     */
    public String getEncryptionSymAlgorithm() {
        return encryptionSymAlgorithm;
    }

    /**
     * Specifies the encryption algorithm
     *
     * @param encryptionSymAlgorithm The algo to use for encryption
     */
    public void setEncryptionSymAlgorithm(String encryptionSymAlgorithm) {
        this.encryptionSymAlgorithm = encryptionSymAlgorithm;
    }

    /**
     * Returns the encryption key transport algorithm
     *
     * @return the key transport algorithm as string
     */
    public String getEncryptionKeyTransportAlgorithm() {
        return encryptionKeyTransportAlgorithm;
    }

    /**
     * Specifies the encryption key transport algorithm
     *
     * @param encryptionKeyTransportAlgorithm
     *         the encryption key transport algorithm as string
     */
    public void setEncryptionKeyTransportAlgorithm(String encryptionKeyTransportAlgorithm) {
        this.encryptionKeyTransportAlgorithm = encryptionKeyTransportAlgorithm;
    }

    public X509Certificate getEncryptionUseThisCertificate() {
        return encryptionUseThisCertificate;
    }

    public void setEncryptionUseThisCertificate(X509Certificate encryptionUseThisCertificate) {
        this.encryptionUseThisCertificate = encryptionUseThisCertificate;
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

    /**
     * returns the KeyIdentifierType which will be used in the secured document
     *
     * @return The KeyIdentifierType
     */
    public Constants.KeyIdentifierType getEncryptionKeyIdentifierType() {
        return encryptionKeyIdentifierType;
    }

    /**
     * Specifies the KeyIdentifierType to use in the secured document
     *
     * @param encryptionKeyIdentifierType
     */
    public void setEncryptionKeyIdentifierType(Constants.KeyIdentifierType encryptionKeyIdentifierType) {
        this.encryptionKeyIdentifierType = encryptionKeyIdentifierType;
    }

    private List<SecurePart> signatureParts = new LinkedList<SecurePart>();
    private String signatureAlgorithm;
    private String signatureDigestAlgorithm;
    private String signatureCanonicalizationAlgorithm;
    private Class signatureCryptoClass;
    private KeyStore signatureKeyStore;
    private String signatureUser;
    private Constants.KeyIdentifierType signatureKeyIdentifierType;
    private boolean useSingleCert = true;

    public void addSignaturePart(SecurePart securePart) {
        signatureParts.add(securePart);
    }

    public List<SecurePart> getSignatureSecureParts() {
        return signatureParts;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getSignatureDigestAlgorithm() {
        return signatureDigestAlgorithm;
    }

    public void setSignatureDigestAlgorithm(String signatureDigestAlgorithm) {
        this.signatureDigestAlgorithm = signatureDigestAlgorithm;
    }

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

    public Class getSignatureCryptoClass() {
        return signatureCryptoClass;
    }

    public void setSignatureCryptoClass(Class signatureCryptoClass) {
        this.signatureCryptoClass = signatureCryptoClass;
    }

    private Crypto cachedSignatureCrypto;
    private Class cachedSignatureCryptoClass;
    private KeyStore cachedSignatureKeyStore;

    public Crypto getSignatureCrypto() throws WSSecurityException {

        if (this.getSignatureKeyStore() == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureKeyStoreNotSet");
        }

        if (this.getSignatureCryptoClass() == cachedSignatureCryptoClass
                && this.getSignatureKeyStore() == cachedSignatureKeyStore) {
            return cachedSignatureCrypto;
        }

        Class signatureCryptoClass = org.swssf.crypto.Merlin.class;
        if (this.getSignatureCryptoClass() != null) {
            signatureCryptoClass = this.getSignatureCryptoClass();
            if (!CryptoBase.class.isAssignableFrom(signatureCryptoClass)) {
                throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureCryptoClassWrong");
            }
        }

        try {
            CryptoBase signatureCrypto = (CryptoBase) signatureCryptoClass.newInstance();
            signatureCrypto.setKeyStore(this.getSignatureKeyStore());
            cachedSignatureCrypto = signatureCrypto;
            cachedSignatureCryptoClass = signatureCryptoClass;
            cachedSignatureKeyStore = this.getSignatureKeyStore();
            return signatureCrypto;
        } catch (Exception e) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureCryptoFailure", e);
        }
    }

    public Constants.KeyIdentifierType getSignatureKeyIdentifierType() {
        return signatureKeyIdentifierType;
    }

    public void setSignatureKeyIdentifierType(Constants.KeyIdentifierType signatureKeyIdentifierType) {
        this.signatureKeyIdentifierType = signatureKeyIdentifierType;
    }

    public boolean isUseSingleCert() {
        return useSingleCert;
    }

    public void setUseSingleCert(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }

    private Integer timestampTTL = 300;

    public Integer getTimestampTTL() {
        return timestampTTL;
    }

    public void setTimestampTTL(Integer timestampTTL) {
        this.timestampTTL = timestampTTL;
    }

    /**
     * Returns the actual set actions
     *
     * @return The Actions in applied order
     */
    public Constants.Action[] getOutAction() {
        return outAction;
    }

    /**
     * Specifies how to secure the document eg. Timestamp, Signature, Encrypt
     *
     * @param outAction
     */
    public void setOutAction(Constants.Action[] outAction) {
        this.outAction = outAction;
    }

    public String getSignatureCanonicalizationAlgorithm() {
        return signatureCanonicalizationAlgorithm;
    }

    public void setSignatureCanonicalizationAlgorithm(String signatureCanonicalizationAlgorithm) {
        this.signatureCanonicalizationAlgorithm = signatureCanonicalizationAlgorithm;
    }

    private Class signatureVerificationCryptoClass;
    private KeyStore signatureVerificationKeyStore;

    public KeyStore getSignatureVerificationKeyStore() {
        return signatureVerificationKeyStore;
    }

    public void loadSignatureVerificationKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        this.signatureVerificationKeyStore = keyStore;
    }

    public Class getSignatureVerificationCryptoClass() {
        if (signatureVerificationCryptoClass != null) {
            return signatureVerificationCryptoClass;
        }
        return org.swssf.crypto.Merlin.class;
    }

    public void setSignatureVerificationCryptoClass(Class signatureVerificationCryptoClass) {
        this.signatureVerificationCryptoClass = signatureVerificationCryptoClass;
    }

    private Crypto cachedSignatureVerificationCrypto;
    private Class cachedSignatureVerificationCryptoClass;
    private KeyStore cachedSignatureVerificationKeyStore;

    public Crypto getSignatureVerificationCrypto() throws WSSecurityException {

        if (this.getSignatureVerificationKeyStore() == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureVerificationKeyStoreNotSet");
        }

        if (this.getSignatureVerificationCryptoClass() == cachedSignatureVerificationCryptoClass
                && this.getSignatureVerificationKeyStore() == cachedSignatureVerificationKeyStore) {
            return cachedSignatureVerificationCrypto;
        }

        Class signatureVerificationCryptoClass = this.getSignatureVerificationCryptoClass();
        if (!CryptoBase.class.isAssignableFrom(signatureVerificationCryptoClass)) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureVerificationCryptoClassWrong");
        }

        try {
            CryptoBase signatureVerificationCrypto = (CryptoBase) signatureVerificationCryptoClass.newInstance();
            signatureVerificationCrypto.setKeyStore(this.getSignatureVerificationKeyStore());
            cachedSignatureVerificationCrypto = signatureVerificationCrypto;
            cachedSignatureVerificationCryptoClass = signatureVerificationCryptoClass;
            cachedSignatureVerificationKeyStore = this.getSignatureVerificationKeyStore();
            return signatureVerificationCrypto;
        } catch (Exception e) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureVerificationCryptoFailure", e);
        }
    }

    private boolean strictTimestampCheck = true;

    public boolean isStrictTimestampCheck() {
        return strictTimestampCheck;
    }

    public void setStrictTimestampCheck(boolean strictTimestampCheck) {
        this.strictTimestampCheck = strictTimestampCheck;
    }

    private boolean skipDocumentEvents = false;

    /**
     * Returns if the framework is skipping document-events
     *
     * @return true if document-events will be skipped, false otherwise
     */
    public boolean isSkipDocumentEvents() {
        return skipDocumentEvents;
    }

    /**
     * specifies if the framework should forward Document-Events or not
     *
     * @param skipDocumentEvents set to true when document events should be discarded, false otherwise
     */
    public void setSkipDocumentEvents(boolean skipDocumentEvents) {
        this.skipDocumentEvents = skipDocumentEvents;
    }

    private String tokenUser;
    private Constants.UsernameTokenPasswordType usernameTokenPasswordType;

    public String getTokenUser() {
        return tokenUser;
    }

    public void setTokenUser(String tokenUser) {
        this.tokenUser = tokenUser;
    }

    public Constants.UsernameTokenPasswordType getUsernameTokenPasswordType() {
        return usernameTokenPasswordType;
    }

    public void setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType usernameTokenPasswordType) {
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
}
