package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.crypto.Crypto;
import ch.gigerstyle.xmlsec.crypto.CryptoBase;

import javax.security.auth.callback.CallbackHandler;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: May 16, 2010
 * Time: 5:34:15 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SecurityProperties {

    private Class decryptionCryptoClass;
    private KeyStore decryptionKeyStore;
    private String decryptionDefaultAlias;
    private char[] decryptionAliasPassword;
    private CallbackHandler callbackHandler;

    //todo validate after XMLSec instanciation

    public void setDecryptionDefaultAlias(String decryptionDefaultAlias) {
        this.decryptionDefaultAlias = decryptionDefaultAlias;
    }

    public void setDecryptionAliasPassword(char[] decryptionAliasPassword) {
        this.decryptionAliasPassword = decryptionAliasPassword;
    }

    //used as fallback...
    public String getDecryptionDefaultAlias() {
        return decryptionDefaultAlias;
    }

    public char[] getDecryptionAliasPassword() {
        return decryptionAliasPassword;
    }

    public KeyStore getDecryptionKeyStore() {
        return decryptionKeyStore;
    }

    public void loadDecryptionKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        this.decryptionKeyStore = keyStore;
    }

    public Class getDecryptionCryptoClass() {
        return decryptionCryptoClass;
    }

    public void setDecryptionCryptoClass(Class decryptionCryptoClass) {
        this.decryptionCryptoClass = decryptionCryptoClass;
    }

    //todo caching?
    public Crypto getDecryptionCrypto() throws XMLSecurityException {

        if (this.getDecryptionKeyStore() == null) {
            throw new XMLSecurityException(new SecurityConfigurationException("Decryption KeyStore is not set"));
        }

        Class decryptionCryptoClass = ch.gigerstyle.xmlsec.crypto.Merlin.class;
        if (this.getDecryptionCryptoClass() != null) {
            decryptionCryptoClass = this.getDecryptionCryptoClass();
        }
        //todo test instance for CryptoBase class
        try {
            CryptoBase decryptionCrypto = (CryptoBase)decryptionCryptoClass.newInstance();
            decryptionCrypto.setKeyStore(this.getDecryptionKeyStore());
            return decryptionCrypto;
        } catch (Exception e) {
            throw new XMLSecurityException("decryptionCrypto instanciation failed", e);
        }
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

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
    private List<SecurePart> encryptionParts = new ArrayList<SecurePart>();

    public KeyStore getEncryptionKeyStore() {
        return encryptionKeyStore;
    }

    public void loadEncryptionKeystore(URL url, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(url.openStream(), keyStorePassword);
        this.encryptionKeyStore = keyStore;
    }

    public Class getEncryptionCryptoClass() {
        return encryptionCryptoClass;
    }

    public void setEncryptionCryptoClass(Class encryptionCryptoClass) {
        this.encryptionCryptoClass = encryptionCryptoClass;
    }

    //todo caching?
    public Crypto getEncryptionCrypto() throws XMLSecurityException {
        Class encryptionCryptoClass = ch.gigerstyle.xmlsec.crypto.Merlin.class;
        if (this.getEncryptionCryptoClass() != null) {
            encryptionCryptoClass = this.getEncryptionCryptoClass();
        }
        //todo test instance for CryptoBase class
        try {
            CryptoBase encryptionCrypto = (CryptoBase)encryptionCryptoClass.newInstance();
            encryptionCrypto.setKeyStore(this.getEncryptionKeyStore());
            return encryptionCrypto;
        } catch (Exception e) {
            throw new XMLSecurityException("decryptionCrypto instanciation failed", e);
        }
    }

    public void addEncryptionSecurePart(SecurePart securePart){
        encryptionParts.add(securePart);
    }

    public List<SecurePart> getEncryptionSecureParts() {
        return encryptionParts;
    }

    public String getEncryptionSymAlgorithm() {
        return encryptionSymAlgorithm;
    }

    public void setEncryptionSymAlgorithm(String encryptionSymAlgorithm) {
        this.encryptionSymAlgorithm = encryptionSymAlgorithm;
    }

    public String getEncryptionKeyTransportAlgorithm() {
        return encryptionKeyTransportAlgorithm;
    }

    public void setEncryptionKeyTransportAlgorithm(String encryptionKeyTransportAlgorithm) {
        this.encryptionKeyTransportAlgorithm = encryptionKeyTransportAlgorithm;
    }

    public X509Certificate getEncryptionUseThisCertificate() {
        return encryptionUseThisCertificate;
    }

    public void setEncryptionUseThisCertificate(X509Certificate encryptionUseThisCertificate) {
        this.encryptionUseThisCertificate = encryptionUseThisCertificate;
    }

    public String getEncryptionUser() {
        return encryptionUser;
    }

    public void setEncryptionUser(String encryptionUser) {
        this.encryptionUser = encryptionUser;
    }

    public Constants.KeyIdentifierType getEncryptionKeyIdentifierType() {
        return encryptionKeyIdentifierType;
    }

    public void setEncryptionKeyIdentifierType(Constants.KeyIdentifierType encryptionKeyIdentifierType) {
        this.encryptionKeyIdentifierType = encryptionKeyIdentifierType;
    }

    private List<SecurePart> signatureParts = new ArrayList<SecurePart>();
    private String signatureAlgorithm;
    private String signatureDigestAlgorithm;
    private String signatureCanonicalizationAlgorithm;
    private Class signatureCryptoClass;
    private KeyStore signatureKeyStore;
    private String signatureUser;
    private Constants.KeyIdentifierType signatureKeyIdentifierType;

    public void addSignaturePart(SecurePart securePart){
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

    //todo caching?
    public Crypto getSignatureCrypto() throws XMLSecurityException {
        Class signatureCryptoClass = ch.gigerstyle.xmlsec.crypto.Merlin.class;
        if (this.getDecryptionCryptoClass() != null) {
            signatureCryptoClass = this.getSignatureCryptoClass();
        }
        //todo test instance for CryptoBase class
        try {
            CryptoBase signatureCrypto = (CryptoBase)signatureCryptoClass.newInstance();
            signatureCrypto.setKeyStore(this.getSignatureKeyStore());
            return signatureCrypto;
        } catch (Exception e) {
            throw new XMLSecurityException("signatureCrypto instanciation failed", e);
        }
    }

    public Constants.KeyIdentifierType getSignatureKeyIdentifierType() {
        return signatureKeyIdentifierType;
    }

    public void setSignatureKeyIdentifierType(Constants.KeyIdentifierType signatureKeyIdentifierType) {
        this.signatureKeyIdentifierType = signatureKeyIdentifierType;
    }


    private Integer timestampTTL;

    public Integer getTimestampTTL() {
        return timestampTTL;
    }

    public void setTimestampTTL(Integer timestampTTL) {
        this.timestampTTL = timestampTTL;
    }

    public Constants.Action[] getOutAction() {
        return outAction;
    }

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
        return signatureVerificationCryptoClass;
    }

    public void setSignatureVerificationCryptoClass(Class signatureVerificationCryptoClass) {
        this.signatureVerificationCryptoClass = signatureVerificationCryptoClass;
    }

    //todo caching?
    public Crypto getSignatureVerificationCrypto() throws XMLSecurityException {
        Class signatureVerificationCryptoClass = ch.gigerstyle.xmlsec.crypto.Merlin.class;
        if (this.getSignatureVerificationCryptoClass() != null) {
            signatureVerificationCryptoClass = this.getSignatureVerificationCryptoClass();
        }
        //todo test instance for CryptoBase class
        try {
            CryptoBase signatureVerificationCrypto = (CryptoBase)signatureVerificationCryptoClass.newInstance();
            signatureVerificationCrypto.setKeyStore(this.getSignatureVerificationKeyStore());
            return signatureVerificationCrypto;
        } catch (Exception e) {
            throw new XMLSecurityException("decryptionCrypto instanciation failed", e);
        }
    }    
}
