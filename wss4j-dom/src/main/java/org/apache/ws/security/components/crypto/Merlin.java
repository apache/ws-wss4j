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

package org.apache.ws.security.components.crypto;

import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Loader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

/**
 * A Crypto implementation based on two Java KeyStore objects, one being the keystore, and one
 * being the truststore.
 */
public class Merlin extends CryptoBase {
    
    /*
     * Deprecated types
     */
    public static final String OLD_KEYSTORE_FILE = 
        "org.apache.ws.security.crypto.merlin.file";
    
    /*
     * Crypto providers
     */
    public static final String CRYPTO_KEYSTORE_PROVIDER = 
        "org.apache.ws.security.crypto.merlin.keystore.provider";
    public static final String CRYPTO_CERT_PROVIDER =
        "org.apache.ws.security.crypto.merlin.cert.provider";
    
    /*
     * KeyStore configuration types
     */
    public static final String KEYSTORE_FILE = 
        "org.apache.ws.security.crypto.merlin.keystore.file";
    public static final String KEYSTORE_PASSWORD =
        "org.apache.ws.security.crypto.merlin.keystore.password";
    public static final String KEYSTORE_TYPE =
        "org.apache.ws.security.crypto.merlin.keystore.type";
    public static final String KEYSTORE_ALIAS =
        "org.apache.ws.security.crypto.merlin.keystore.alias";
    public static final String KEYSTORE_PRIVATE_PASSWORD =
        "org.apache.ws.security.crypto.merlin.keystore.private.password";
    
    /*
     * TrustStore configuration types
     */
    public static final String LOAD_CA_CERTS =
        "org.apache.ws.security.crypto.merlin.load.cacerts";
    public static final String TRUSTSTORE_FILE =
        "org.apache.ws.security.crypto.merlin.truststore.file";
    public static final String TRUSTSTORE_PASSWORD =
        "org.apache.ws.security.crypto.merlin.truststore.password";
    public static final String TRUSTSTORE_TYPE =
        "org.apache.ws.security.crypto.merlin.truststore.type";
    
    /*
     * CRL configuration
     */
    public static final String X509_CRL_FILE = 
        "org.apache.ws.security.crypto.merlin.x509crl.file";
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(Merlin.class);
    private static final boolean DO_DEBUG = LOG.isDebugEnabled();

    protected static CertificateFactory certFact;
    protected Properties properties = null;
    protected KeyStore keystore = null;
    protected KeyStore truststore = null;
    protected CertStore crlCertStore = null;
    protected boolean loadCACerts = false;
    protected boolean privatePasswordSet = false; 
    
    public Merlin() {
        // default constructor
    }
    
    public Merlin(Properties properties) 
        throws CredentialException, IOException {
        this(properties, Loader.getClassLoader(Merlin.class));
    }

    public Merlin(Properties properties, ClassLoader loader) 
        throws CredentialException, IOException {
        loadProperties(properties, loader);
    }
    
    public void loadProperties(Properties properties) 
        throws CredentialException, IOException {
        loadProperties(properties, Loader.getClassLoader(Merlin.class));
    }
    
    public void loadProperties(Properties properties, ClassLoader loader) 
        throws CredentialException, IOException {
        if (properties == null) {
            return;
        }
        this.properties = properties;
        //
        // Load the provider(s)
        //
        String provider = properties.getProperty(CRYPTO_KEYSTORE_PROVIDER);
        if (provider != null) {
            provider = provider.trim();
        }
        String certProvider = properties.getProperty(CRYPTO_CERT_PROVIDER);
        if (certProvider != null) {
            setCryptoProvider(certProvider);
        }
        //
        // Load the KeyStore
        //
        String alias = properties.getProperty(KEYSTORE_ALIAS);
        if (alias != null) {
            alias = alias.trim();
            defaultAlias = alias;
        }
        String keyStoreLocation = properties.getProperty(KEYSTORE_FILE);
        if (keyStoreLocation == null) {
            keyStoreLocation = properties.getProperty(OLD_KEYSTORE_FILE);
        }
        if (keyStoreLocation != null) {
            keyStoreLocation = keyStoreLocation.trim();
            InputStream is = loadInputStream(loader, keyStoreLocation);

            try {
                String passwd = properties.getProperty(KEYSTORE_PASSWORD, "security");
                if (passwd != null) {
                    passwd = passwd.trim();
                }
                String type = properties.getProperty(KEYSTORE_TYPE, KeyStore.getDefaultType());
                if (type != null) {
                    type = type.trim();
                }
                keystore = load(is, passwd, provider, type);
                if (DO_DEBUG) {
                    LOG.debug(
                        "The KeyStore " + keyStoreLocation + " of type " + type 
                        + " has been loaded"
                    );
                }
                String privatePasswd = properties.getProperty(KEYSTORE_PRIVATE_PASSWORD);
                if (privatePasswd != null) {
                    privatePasswordSet = true;
                }
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } else {
            if (DO_DEBUG) {
                LOG.debug("The KeyStore is not loaded as KEYSTORE_FILE is null");
            }
        }
        
        //
        // Load the TrustStore
        //
        String trustStoreLocation = properties.getProperty(TRUSTSTORE_FILE);
        if (trustStoreLocation != null) {
            trustStoreLocation = trustStoreLocation.trim();
            InputStream is = loadInputStream(loader, trustStoreLocation);

            try {
                String passwd = properties.getProperty(TRUSTSTORE_PASSWORD, "changeit");
                if (passwd != null) {
                    passwd = passwd.trim();
                }
                String type = properties.getProperty(TRUSTSTORE_TYPE, KeyStore.getDefaultType());
                if (type != null) {
                    type = type.trim();
                }
                truststore = load(is, passwd, provider, type);
                if (DO_DEBUG) {
                    LOG.debug(
                        "The TrustStore " + trustStoreLocation + " of type " + type 
                        + " has been loaded"
                    );
                }
                loadCACerts = false;
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } else {
            String loadCacerts = properties.getProperty(LOAD_CA_CERTS, "false");
            if (loadCacerts != null) {
                loadCacerts = loadCacerts.trim();
            }
            if (Boolean.valueOf(loadCacerts).booleanValue()) {
                String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
                if (cacertsPath != null) {
                    cacertsPath = cacertsPath.trim();
                }
                InputStream is = new FileInputStream(cacertsPath);
                try {
                    String cacertsPasswd = properties.getProperty(TRUSTSTORE_PASSWORD, "changeit");
                    if (cacertsPasswd != null) {
                        cacertsPasswd = cacertsPasswd.trim();
                    }
                    truststore = load(is, cacertsPasswd, null, KeyStore.getDefaultType());
                    if (DO_DEBUG) {
                        LOG.debug("CA certs have been loaded");
                    }
                    loadCACerts = true;
                } finally {
                    if (is != null) {
                        is.close();
                    }
                }
            }
        }
        //
        // Load the CRL file
        //
        String crlLocation = properties.getProperty(X509_CRL_FILE);
        if (crlLocation != null) {
            crlLocation = crlLocation.trim();
            InputStream is = loadInputStream(loader, crlLocation);

            try {
                CertificateFactory cf = getCertificateFactory();
                X509CRL crl = (X509CRL)cf.generateCRL(is);
                
                if (provider == null || provider.length() == 0) {
                    crlCertStore = 
                        CertStore.getInstance(
                            "Collection",
                            new CollectionCertStoreParameters(Collections.singletonList(crl))
                        );
                } else {
                    crlCertStore = 
                        CertStore.getInstance(
                            "Collection",
                            new CollectionCertStoreParameters(Collections.singletonList(crl)),
                            provider
                        );
                }
                if (DO_DEBUG) {
                    LOG.debug(
                        "The CRL " + crlLocation + " has been loaded"
                    );
                }
            } catch (Exception e) {
                if (DO_DEBUG) {
                    LOG.debug(e.getMessage(), e);
                }
                throw new CredentialException(CredentialException.IO_ERROR, "ioError00", e);
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        }
    }

    
    /**
     * Load a KeyStore object as an InputStream, using the ClassLoader and location arguments
     */
    public static InputStream loadInputStream(ClassLoader loader, String location) 
        throws CredentialException, IOException {
        InputStream is = null;
        if (location != null) {
            java.net.URL url = Loader.getResource(loader, location);
            if (url != null) {
                is = url.openStream();
            }
    
            //
            // If we don't find it, then look on the file system.
            //
            if (is == null) {
                try {
                    is = new FileInputStream(location);
                } catch (Exception e) {
                    if (DO_DEBUG) {
                        LOG.debug(e.getMessage(), e);
                    }
                    throw new CredentialException(
                        CredentialException.IO_ERROR, "proxyNotFound", new Object[]{location}, e
                    );
                }
            }
        }
        return is;
    }
    

    /**
     * Loads the keystore from an <code>InputStream </code>.
     * <p/>
     *
     * @param input <code>InputStream</code> to read from
     * @throws CredentialException
     */
    public KeyStore load(InputStream input, String storepass, String provider, String type) 
        throws CredentialException {
        KeyStore ks = null;
        
        try {
            if (provider == null || provider.length() == 0) {
                ks = KeyStore.getInstance(type);
            } else {
                ks = KeyStore.getInstance(type, provider);
            }
                    
            ks.load(input, (storepass == null || storepass.length() == 0) 
                ? new char[0] : storepass.toCharArray());
        } catch (IOException e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.IO_ERROR, "ioError00", e);
        } catch (GeneralSecurityException e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.SEC_ERROR, "secError00", e);
        } catch (Exception e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.FAILURE, "error00", e);
        }
        return ks;
    }
    
    //
    // Accessor methods
    //
    
    /**
     * Gets the Keystore that was loaded
     *
     * @return the Keystore
     */
    public KeyStore getKeyStore() {
        return keystore;
    }
    
    /**
     * Set the Keystore on this Crypto instance
     *
     * @param keyStore the Keystore to set
     */
    public void setKeyStore(KeyStore keyStore) {
        keystore = keyStore;
    }
    
    /**
     * Gets the trust store that was loaded by the underlying implementation
     *
     * @return the trust store
     */
    public KeyStore getTrustStore() {
        return truststore;
    }
    
    /**
     * Set the trust store on this Crypto instance
     *
     * @param trustStore the trust store to set
     */
    public void setTrustStore(KeyStore trustStore) {
        truststore = trustStore;
    }
    
    /**
     * Set the CertStore from which to obtain a list of CRLs for Certificate Revocation
     * checking.
     * @param crlCertStore the CertStore from which to obtain a list of CRLs for Certificate 
     * Revocation checking.
     */
    public void setCRLCertStore(CertStore crlCertStore) {
        this.crlCertStore = crlCertStore;
    }
    
    /**
     * Get the CertStore from which to obtain a list of CRLs for Certificate Revocation
     * checking.
     * @return the CertStore from which to obtain a list of CRLs for Certificate 
     * Revocation checking.
     */
    public CertStore getCRLCertStore() {
        return crlCertStore;
    }
    
    /**
     * Singleton certificate factory for this Crypto instance.
     * <p/>
     *
     * @return Returns a <code>CertificateFactory</code> to construct
     *         X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    @Override
    public CertificateFactory getCertificateFactory() throws WSSecurityException {
        String provider = getCryptoProvider();
        String keyStoreProvider = null;
        if (keystore != null) {
            keyStoreProvider = keystore.getProvider().getName();
        }

        //Try to find a CertificateFactory that generates certs that are fully
        //compatible with the certs in the KeyStore  (Sun -> Sun, BC -> BC, etc...)
        CertificateFactory factory = null;
        if (provider != null) {
            factory = certFactMap.get(provider);
        } else if (keyStoreProvider != null) {
            factory = 
                certFactMap.get(mapKeystoreProviderToCertProvider(keyStoreProvider));
            if (factory == null) {
                factory = certFactMap.get(keyStoreProvider);                
            }
        } else {
            factory = certFactMap.get("DEFAULT");
        }
        if (factory == null) {
            try {
                if (provider == null || provider.length() == 0) {
                    if (keyStoreProvider != null && keyStoreProvider.length() != 0) {
                        try {
                            factory = 
                                CertificateFactory.getInstance(
                                    "X.509", mapKeystoreProviderToCertProvider(keyStoreProvider)
                                );
                            certFactMap.put(keyStoreProvider, factory);
                            certFactMap.put(
                                mapKeystoreProviderToCertProvider(keyStoreProvider), factory
                            );
                        } catch (Exception ex) {
                            LOG.debug(ex);
                            //Ignore, we'll just use the default since they didn't specify one.
                            //Hopefully that will work for them.
                        }
                    }
                    if (factory == null) {
                        factory = CertificateFactory.getInstance("X.509");
                        certFactMap.put("DEFAULT", factory);
                    }
                } else {
                    factory = CertificateFactory.getInstance("X.509", provider);
                    certFactMap.put(provider, factory);
                }
                certFactMap.put(factory.getProvider().getName(), factory);
            } catch (CertificateException e) {
                throw new WSSecurityException(
                    WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "unsupportedCertType",
                    null, e
                );
            } catch (NoSuchProviderException e) {
                throw new WSSecurityException(
                    WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "noSecProvider",
                    null, e
                );
            }
        }
        return factory;
    }
    
    private String mapKeystoreProviderToCertProvider(String s) {
        if ("SunJSSE".equals(s)) {
            return "SUN";
        }
        return s;
    }
    
    /**
     * Retrieves the identifier name of the default certificate. This should be the certificate 
     * that is used for signature and encryption. This identifier corresponds to the certificate 
     * that should be used whenever KeyInfo is not present in a signed or an encrypted 
     * message. May return null. The identifier is implementation specific, e.g. it could be the
     * KeyStore alias.
     *
     * @return name of the default X509 certificate.
     */
    @Override
    public String getDefaultX509Identifier() throws WSSecurityException {
        if (defaultAlias != null) {
            return defaultAlias;
        }
        
        if (keystore != null) {
            try {
                Enumeration<String> as = keystore.aliases();
                if (as.hasMoreElements()) {
                    String alias = as.nextElement();
                    if (!as.hasMoreElements()) {
                        defaultAlias = alias;
                        return alias;
                    }
                }
            } catch (KeyStoreException ex) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "keystore", null, ex
                );
            } 
        }
        return null;
    }
    
    //
    // Keystore-specific Crypto functionality methods
    //

    /**
     * Get an X509Certificate (chain) corresponding to the CryptoType argument. The supported
     * types are as follows:
     * 
     * TYPE.ISSUER_SERIAL - A certificate (chain) is located by the issuer name and serial number
     * TYPE.THUMBPRINT_SHA1 - A certificate (chain) is located by the SHA1 of the (root) cert
     * TYPE.SKI_BYTES - A certificate (chain) is located by the SKI bytes of the (root) cert
     * TYPE.SUBJECT_DN - A certificate (chain) is located by the Subject DN of the (root) cert
     * TYPE.ALIAS - A certificate (chain) is located by an alias, which for this implementation
     * means an alias of the keystore or truststore.
     */
    public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
        if (cryptoType == null) {
            return null;
        }
        CryptoType.TYPE type = cryptoType.getType();
        X509Certificate[] certs = null;
        switch (type) {
        case ISSUER_SERIAL: {
            certs = getX509Certificates(cryptoType.getIssuer(), cryptoType.getSerial());
            break;
        }
        case THUMBPRINT_SHA1: {
            certs = getX509Certificates(cryptoType.getBytes());
            break;
        }
        case SKI_BYTES: {
            certs = getX509CertificatesSKI(cryptoType.getBytes());
            break;
        }
        case SUBJECT_DN: {
            certs = getX509CertificatesSubjectDN(cryptoType.getSubjectDN());
            break;
        }
        case ALIAS: {
            certs = getX509Certificates(cryptoType.getAlias());
            break;
        }
        }
        return certs;
    }

    /**
     * Get the implementation-specific identifier corresponding to the cert parameter. In this 
     * case, the identifier corresponds to a KeyStore alias.
     * @param cert The X509Certificate for which to search for an identifier
     * @return the identifier corresponding to the cert parameter
     * @throws WSSecurityException
     */
    public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
        String identifier = null;
        
        if (keystore != null) {
            identifier = getIdentifier(cert, keystore);
        }
        
        if (identifier == null && truststore != null) {
            identifier = getIdentifier(cert, truststore);
        }
        
        return identifier;
    }
    
    /**
     * Gets the private key corresponding to the certificate.
     *
     * @param certificate The X509Certificate corresponding to the private key
     * @param callbackHandler The callbackHandler needed to get the password
     * @return The private key
     */
    public PrivateKey getPrivateKey(
        X509Certificate certificate, 
        CallbackHandler callbackHandler
    ) throws WSSecurityException {
        if (keystore == null) {
            throw new WSSecurityException("The keystore is null");
        }
        if (callbackHandler == null) {
            throw new WSSecurityException("The CallbackHandler is null");
        }
        
        String identifier = getIdentifier(certificate, keystore);
        try {
            if (identifier == null || !keystore.isKeyEntry(identifier)) {
                String msg = "Cannot find key for alias: [" + identifier + "]";
                String logMsg = createKeyStoreErrorMessage(keystore);
                LOG.error(msg + logMsg);
                throw new WSSecurityException(msg);
            }
            String password = getPassword(identifier, callbackHandler);
            if (password == null && privatePasswordSet) {
                password = properties.getProperty(KEYSTORE_PRIVATE_PASSWORD);
                if (password != null) {
                    password = password.trim();
                }
            }
            Key keyTmp = keystore.getKey(identifier, password == null 
                                         ? new char[]{} : password.toCharArray());
            if (!(keyTmp instanceof PrivateKey)) {
                String msg = "Key is not a private key, alias: [" + identifier + "]";
                String logMsg = createKeyStoreErrorMessage(keystore);
                LOG.error(msg + logMsg);
                throw new WSSecurityException(msg);
            }
            return (PrivateKey) keyTmp;
        } catch (KeyStoreException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        } catch (UnrecoverableKeyException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        } catch (NoSuchAlgorithmException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        }
    }
    
    /**
     * Gets the private key corresponding to the identifier.
     *
     * @param identifier The implementation-specific identifier corresponding to the key
     * @param password The password needed to get the key
     * @return The private key
     */
    public PrivateKey getPrivateKey(
        String identifier,
        String password
    ) throws WSSecurityException {
        if (keystore == null) {
            throw new WSSecurityException("The keystore is null");
        }
        try {
            if (identifier == null || !keystore.isKeyEntry(identifier)) {
                String msg = "Cannot find key for alias: [" + identifier + "]";
                String logMsg = createKeyStoreErrorMessage(keystore);
                LOG.error(msg + logMsg);
                throw new WSSecurityException(msg);
            }
            if (password == null && privatePasswordSet) {
                password = properties.getProperty(KEYSTORE_PRIVATE_PASSWORD);
                if (password != null) {
                    password = password.trim();
                }
            }
            Key keyTmp = keystore.getKey(identifier, password == null 
                                         ? new char[]{} : password.toCharArray());
            if (!(keyTmp instanceof PrivateKey)) {
                String msg = "Key is not a private key, alias: [" + identifier + "]";
                String logMsg = createKeyStoreErrorMessage(keystore);
                LOG.error(msg + logMsg);
                throw new WSSecurityException(msg);
            }
            return (PrivateKey) keyTmp;
        } catch (KeyStoreException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        } catch (UnrecoverableKeyException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        } catch (NoSuchAlgorithmException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
            );
        }
    }
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     * Uses the CertPath API to validate a given certificate chain.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    @Deprecated
    public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
        return verifyTrust(certs, false);
    }
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     * Uses the CertPath API to validate a given certificate chain.
     *
     * @param certs Certificate chain to validate
     * @param enableRevocation whether to enable CRL verification or not
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    public boolean verifyTrust(
        X509Certificate[] certs, 
        boolean enableRevocation
    ) throws WSSecurityException {
        try {
            // Generate cert path
            List<X509Certificate> certList = Arrays.asList(certs);
            CertPath path = getCertificateFactory().generateCertPath(certList);

            Set<TrustAnchor> set = new HashSet<TrustAnchor>();
            if (truststore != null) {
                Enumeration<String> truststoreAliases = truststore.aliases();
                while (truststoreAliases.hasMoreElements()) {
                    String alias = truststoreAliases.nextElement();
                    X509Certificate cert = 
                        (X509Certificate) truststore.getCertificate(alias);
                    if (cert != null) {
                        TrustAnchor anchor = 
                            new TrustAnchor(cert, cert.getExtensionValue(NAME_CONSTRAINTS_OID));
                        set.add(anchor);
                    }
                }
            }

            //
            // Add certificates from the keystore - only if there is no TrustStore, apart from
            // the case that the truststore is the JDK CA certs. This behaviour is preserved
            // for backwards compatibility reasons
            //
            if (keystore != null && (truststore == null || loadCACerts)) {
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate cert = 
                        (X509Certificate) keystore.getCertificate(alias);
                    if (cert != null) {
                        TrustAnchor anchor = 
                            new TrustAnchor(cert, cert.getExtensionValue(NAME_CONSTRAINTS_OID));
                        set.add(anchor);
                    }
                }
            }

            PKIXParameters param = new PKIXParameters(set);
            param.setRevocationEnabled(enableRevocation);
            if (enableRevocation && crlCertStore != null) {
                param.addCertStore(crlCertStore);
            }

            // Verify the trust path using the above settings
            String provider = getCryptoProvider();
            CertPathValidator validator = null;
            if (provider == null || provider.length() == 0) {
                validator = CertPathValidator.getInstance("PKIX");
            } else {
                validator = CertPathValidator.getInstance("PKIX", provider);
            }
            validator.validate(path, param);
            return true;
        } catch (java.security.NoSuchProviderException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.NoSuchAlgorithmException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "certpath", new Object[] { e.getMessage() },
                    e
                );
        } catch (java.security.cert.CertificateException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath", 
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.InvalidAlgorithmParameterException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.cert.CertPathValidatorException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.KeyStoreException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (NullPointerException e) {
                // NPE thrown by JDK 1.7 for one of the test cases
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        }
    }
    
    /**
     * Evaluate whether a given public key should be trusted.
     * 
     * @param publicKey The PublicKey to be evaluated
     * @return whether the PublicKey parameter is trusted or not
     */
    public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
        //
        // If the public key is null, do not trust the signature
        //
        if (publicKey == null) {
            return false;
        }
        
        //
        // Search the keystore for the transmitted public key (direct trust)
        //
        boolean trust = findPublicKeyInKeyStore(publicKey, keystore);
        if (trust) {
            return true;
        } else {
            //
            // Now search the truststore for the transmitted public key (direct trust)
            //
            trust = findPublicKeyInKeyStore(publicKey, truststore);
            if (trust) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given serial number and issuer string.
     *
     * @param issuer The Issuer String
     * @param serialNumber The serial number of the certificate
     * @return an X509 Certificate (chain) corresponding to the found certificate(s)
     * @throws WSSecurityException
     */
    private X509Certificate[] getX509Certificates(
        String issuer, 
        BigInteger serialNumber
    ) throws WSSecurityException {
        //
        // Convert the subject DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        Object issuerName = null;
        try {
            X500Principal issuerRDN = new X500Principal(issuer);
            issuerName = createBCX509Name(issuerRDN.getName());
        } catch (java.lang.IllegalArgumentException ex) {
            issuerName = createBCX509Name(issuer);
        }
        Certificate[] certs = null;
        if (keystore != null) {
            certs = getCertificates(issuerName, serialNumber, keystore);
        }

        //If we can't find the issuer in the keystore then look at the truststore
        if ((certs == null || certs.length == 0) && truststore != null) {
            certs = getCertificates(issuerName, serialNumber, truststore);
        }
        
        if ((certs == null || certs.length == 0)) {
            return null;
        }
        
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }
    
    /**
     * Get an X509 Certificate (chain) of the X500Principal argument in the supplied KeyStore 
     * @param subjectRDN either an X500Principal or a BouncyCastle X509Name instance.
     * @param store The KeyStore
     * @return an X509 Certificate (chain)
     * @throws WSSecurityException
     */
    private Certificate[] getCertificates(
        Object issuerRDN, 
        BigInteger serialNumber, 
        KeyStore store
    ) throws WSSecurityException {
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                Certificate cert = null;
                Certificate[] certs = store.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = store.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                    certs = new Certificate[]{cert};
                } else {
                    cert = certs[0];
                }
                if (cert instanceof X509Certificate) {
                    X509Certificate x509cert = (X509Certificate) cert;
                    if (x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
                        Object certName = 
                            createBCX509Name(x509cert.getIssuerX500Principal().getName());
                        if (certName.equals(issuerRDN)) {
                            return certs;
                        }
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "keystore", null, e
            );
        }
        return new Certificate[]{};
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given Thumbprint.
     *
     * @param thumbprint The SHA1 thumbprint info bytes
     * @return the X509 Certificate (chain) that was found (can be null)
     * @throws WSSecurityException if problems during keystore handling or wrong certificate
     */
    private X509Certificate[] getX509Certificates(byte[] thumbprint) throws WSSecurityException {
        MessageDigest sha = null;
        
        try {
            sha = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSHA1availabe", null, e
            );
        }
        Certificate[] certs = null;
        if (keystore != null) {
            certs = getCertificates(thumbprint, keystore, sha);
        }

        //If we can't find the issuer in the keystore then look at the truststore
        if ((certs == null || certs.length == 0) && truststore != null) {
            certs = getCertificates(thumbprint, truststore, sha);
        }
        
        if ((certs == null || certs.length == 0)) {
            return null;
        }
        
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }

    /**
     * Get an X509 Certificate (chain) of the X500Principal argument in the supplied KeyStore 
     * @param subjectRDN either an X500Principal or a BouncyCastle X509Name instance.
     * @param store The KeyStore
     * @return an X509 Certificate (chain)
     * @throws WSSecurityException
     */
    private Certificate[] getCertificates(
        byte[] thumbprint, 
        KeyStore store,
        MessageDigest sha
    ) throws WSSecurityException {
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                Certificate cert = null;
                Certificate[] certs = store.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = store.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                    certs = new Certificate[]{cert};
                } else {
                    cert = certs[0];
                }
                if (cert instanceof X509Certificate) {
                    X509Certificate x509cert = (X509Certificate) cert;
                    try {
                        sha.update(x509cert.getEncoded());
                    } catch (CertificateEncodingException ex) {
                        throw new WSSecurityException(
                            WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError",
                            null, ex
                        );
                    }
                    byte[] data = sha.digest();

                    if (Arrays.equals(data, thumbprint)) {
                        return certs;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "keystore", null, e
            );
        }
        return new Certificate[]{};
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given SubjectKeyIdentifier.
     *
     * @param skiBytes The SKI bytes
     * @return the X509 certificate (chain) that was found (can be null)
     */
    private X509Certificate[] getX509CertificatesSKI(byte[] skiBytes) throws WSSecurityException {
        Certificate[] certs = null;
        if (keystore != null) {
            certs = getCertificates(skiBytes, keystore);
        }

        //If we can't find the issuer in the keystore then look at the truststore
        if ((certs == null || certs.length == 0) && truststore != null) {
            certs = getCertificates(skiBytes, truststore);
        }
        
        if ((certs == null || certs.length == 0)) {
            return null;
        }
        
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }
    
    /**
     * Get an X509 Certificate (chain) of the X500Principal argument in the supplied KeyStore 
     * @param subjectRDN either an X500Principal or a BouncyCastle X509Name instance.
     * @param store The KeyStore
     * @return an X509 Certificate (chain)
     * @throws WSSecurityException
     */
    private Certificate[] getCertificates(
        byte[] skiBytes, 
        KeyStore store
    ) throws WSSecurityException {
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                Certificate cert = null;
                Certificate[] certs = store.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = store.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                    certs = new Certificate[]{cert};
                } else {
                    cert = certs[0];
                }
                if (cert instanceof X509Certificate) {
                    X509Certificate x509cert = (X509Certificate) cert;
                    byte[] data = getSKIBytesFromCert(x509cert);
                    if (data.length == skiBytes.length && Arrays.equals(data, skiBytes)) {
                        return certs;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "keystore", null, e
            );
        }
        return new Certificate[]{};
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given DN of the subject of the certificate
     *
     * @param subjectDN The DN of subject to look for
     * @return An X509 Certificate (chain) with the same DN as given in the parameters
     * @throws WSSecurityException
     */
    private X509Certificate[] getX509CertificatesSubjectDN(String subjectDN) throws WSSecurityException {
        //
        // Convert the subject DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        Object subject;
        try {
            X500Principal subjectRDN = new X500Principal(subjectDN);
            subject = createBCX509Name(subjectRDN.getName());
        } catch (java.lang.IllegalArgumentException ex) {
            subject = createBCX509Name(subjectDN);
        }
        
        Certificate[] certs = null;
        if (keystore != null) {
            certs = getCertificates(subject, keystore);
        }

        //If we can't find the issuer in the keystore then look at the truststore
        if ((certs == null || certs.length == 0) && truststore != null) {
            certs = getCertificates(subject, truststore);
        }
        
        if ((certs == null || certs.length == 0)) {
            return null;
        }
        
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }
    
    /**
     * Get an X509 Certificate (chain) that correspond to the identifier. For this implementation,
     * the identifier corresponds to the KeyStore alias.
     * 
     * @param identifier The identifier that corresponds to the returned certs
     * @return an X509 Certificate (chain) that corresponds to the identifier
     */
    private X509Certificate[] getX509Certificates(String identifier) throws WSSecurityException {
        Certificate[] certs = null;
        try {
            if (keystore != null) {
                // There's a chance that there can only be a set of trust stores
                certs = keystore.getCertificateChain(identifier);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    Certificate cert = keystore.getCertificate(identifier);
                    if (cert != null) {
                        certs = new Certificate[]{cert};
                    }
                }
            }

            if (certs == null && truststore != null) {
                // Now look into the trust stores
                certs = truststore.getCertificateChain(identifier);
                if (certs == null) {
                    Certificate cert = truststore.getCertificate(identifier);
                    if (cert != null) {
                        certs = new Certificate[]{cert};
                    }
                }
            }

            if (certs == null) {
                return null;
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "keystore", null, e);
        }

        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }
    
    /**
     * Find the Public Key in a keystore. 
     */
    private boolean findPublicKeyInKeyStore(PublicKey publicKey, KeyStore keyStoreToSearch) {
        if (keyStoreToSearch == null) {
            return false;
        }
        try {
            for (Enumeration<String> e = keyStoreToSearch.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                Certificate[] certs = keyStoreToSearch.getCertificateChain(alias);
                Certificate cert;
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = keyStoreToSearch.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                } else {
                    cert = certs[0];
                }
                if (!(cert instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509cert = (X509Certificate) cert;
                if (publicKey.equals(x509cert.getPublicKey())) {
                    return true;
                }
            }
        } catch (KeyStoreException e) {
            return false;
        }
        return false;
    }
    
    /**
     * Get an X509 Certificate (chain) of the X500Principal argument in the supplied KeyStore 
     * @param subjectRDN either an X500Principal or a BouncyCastle X509Name instance.
     * @param store The KeyStore
     * @return an X509 Certificate (chain)
     * @throws WSSecurityException
     */
    private Certificate[] getCertificates(Object subjectRDN, KeyStore store) 
        throws WSSecurityException {
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                Certificate cert = null;
                Certificate[] certs = store.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = store.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                    certs = new Certificate[]{cert};
                } else {
                    cert = certs[0];
                }
                if (cert instanceof X509Certificate) {
                    X500Principal foundRDN = ((X509Certificate) cert).getSubjectX500Principal();
                    Object certName = createBCX509Name(foundRDN.getName());

                    if (subjectRDN.equals(certName)) {
                        return certs;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "keystore", null, e
            );
        }
        return new Certificate[]{};
    }
    
    private static String createKeyStoreErrorMessage(KeyStore keystore) throws KeyStoreException {
        Enumeration<String> aliases = keystore.aliases();
        StringBuilder sb = new StringBuilder(keystore.size() * 7);
        boolean firstAlias = true;
        while (aliases.hasMoreElements()) {
            if (!firstAlias) {
                sb.append(", ");
            }
            sb.append(aliases.nextElement());
            firstAlias = false;
        }
        String msg = " in keystore of type [" + keystore.getType()
            + "] from provider [" + keystore.getProvider()
            + "] with size [" + keystore.size() + "] and aliases: {"
            + sb.toString() + "}";
        return msg;
    }
    
    /**
     * Get an implementation-specific identifier that corresponds to the X509Certificate. In
     * this case, the identifier is the KeyStore alias.
     * @param cert The X509Certificate corresponding to the returned identifier
     * @param store The KeyStore to search
     * @return An implementation-specific identifier that corresponds to the X509Certificate
     */
    private String getIdentifier(X509Certificate cert, KeyStore store)
        throws WSSecurityException {
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                String alias = e.nextElement();
                
                Certificate[] certs = store.getCertificateChain(alias);
                Certificate retrievedCert = null;
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a  result.
                    retrievedCert = store.getCertificate(alias);
                    if (retrievedCert == null) {
                        continue;
                    }
                } else {
                    retrievedCert = certs[0];
                }
                if (!(retrievedCert instanceof X509Certificate)) {
                    continue;
                }
                if (retrievedCert.equals(cert)) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "keystore", null, e);
        }
        return null;
    }
    
    /**
     * Get a password from the CallbackHandler
     * @param identifier The identifier to give to the Callback
     * @param cb The CallbackHandler
     * @return The password retrieved from the CallbackHandler
     * @throws WSSecurityException
     */
    private String getPassword(
        String identifier,
        CallbackHandler cb
    ) throws WSSecurityException {
        WSPasswordCallback pwCb = 
            new WSPasswordCallback(identifier, WSPasswordCallback.DECRYPT);
        try {
            Callback[] callbacks = new Callback[]{pwCb};
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{identifier}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{identifier}, 
                e
            );
        }

        return pwCb.getPassword();
    }
    
    
}
