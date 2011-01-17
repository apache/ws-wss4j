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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.util.Loader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Properties;

public abstract class AbstractCrypto extends CryptoBase {
    
    /*
     * Deprecated types
     */
    public static final String OLD_KEYSTORE_FILE = 
        "org.apache.ws.security.crypto.merlin.file";
    public static final String OLD_CRYPTO_PROVIDER = 
        "org.apache.ws.security.crypto.merlin.keystore.provider";
    public static final String OLD_CRYPTO_CERT_PROVIDER =
        "org.apache.ws.security.crypto.merlin.cert.provider";
    
    /*
     * Crypto provider
     */
    public static final String CRYPTO_PROVIDER = 
        "org.apache.ws.security.crypto.merlin.crypto.provider";
    
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
    
    private static final Log log = LogFactory.getLog(AbstractCrypto.class.getName());
    private static final boolean doDebug = log.isDebugEnabled();

    protected static CertificateFactory certFact;
    protected Properties properties = null;
    
    public AbstractCrypto() {
        // default constructor
    }
    
    public AbstractCrypto(Properties properties) 
        throws CredentialException, IOException {
        this(properties, Loader.getClassLoader(AbstractCrypto.class));
    }

    public AbstractCrypto(Properties properties, ClassLoader loader) 
        throws CredentialException, IOException {
        loadProperties(properties, loader);
    }
    
    public void loadProperties(Properties properties) 
        throws CredentialException, IOException {
        loadProperties(properties, Loader.getClassLoader(AbstractCrypto.class));
    }
    
    public void loadProperties(Properties properties, ClassLoader loader) 
        throws CredentialException, IOException {
        if (properties == null) {
            return;
        }
        this.properties = properties;
        String provider = properties.getProperty(CRYPTO_PROVIDER);
        if (provider == null) {
            provider = properties.getProperty(OLD_CRYPTO_PROVIDER);
        }
        if (provider != null) {
            provider = provider.trim();
        }
        //
        // Load the KeyStore
        //
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
                if (doDebug) {
                    log.debug(
                        "The KeyStore " + keyStoreLocation + " of type " + type 
                        + " has been loaded"
                    );
                }
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } else {
            if (doDebug) {
                log.debug("The KeyStore is not loaded as KEYSTORE_FILE is null");
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
                if (doDebug) {
                    log.debug(
                        "The TrustStore " + trustStoreLocation + " of type " + type 
                        + " has been loaded"
                    );
                }
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
                    if (doDebug) {
                        log.debug("CA certs have been loaded");
                    }
                } finally {
                    if (is != null) {
                        is.close();
                    }
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
                    if (doDebug) {
                        log.debug(e.getMessage(), e);
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
            if (doDebug) {
                log.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.IO_ERROR, "ioError00", e);
        } catch (GeneralSecurityException e) {
            if (doDebug) {
                log.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.SEC_ERROR, "secError00", e);
        } catch (Exception e) {
            if (doDebug) {
                log.debug(e.getMessage(), e);
            }
            throw new CredentialException(CredentialException.FAILURE, "error00", e);
        }
        return ks;
    }

    public String
    getCryptoProvider() {
        if (cryptoProvider != null) {
            return cryptoProvider;
        } else {
            if (properties == null) {
                return null;
            }
            String provider = properties.getProperty(CRYPTO_PROVIDER);
            if (provider == null) {
                provider = properties.getProperty(OLD_CRYPTO_CERT_PROVIDER);
            }
            if (provider != null) {
                provider = provider.trim();
            }
            return provider;
        }
    }
    
    /**
     * Retrieves the alias name of the default certificate which has been
     * specified as a property. This should be the certificate that is used for
     * signature and encryption. This alias corresponds to the certificate that
     * should be used whenever KeyInfo is not present in a signed or
     * an encrypted message. May return null.
     *
     * @return alias name of the default X509 certificate
     */
    public String getDefaultX509Alias() {
        if (defaultAlias != null) {
            return defaultAlias;
        } else {
            if (properties == null) {
                return null;
            }
            String alias = properties.getProperty(KEYSTORE_ALIAS);
            if (alias != null) {
                alias = alias.trim();
            }
            return alias;
        }
    }
}
