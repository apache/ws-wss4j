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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.Properties;

/**
 * A Crypto implementation based on two Java KeyStore objects, one being the keystore, and one
 * being the truststore. This Crypto implementation extends the default Merlin implementation by
 * allowing loading of keystores using a null InputStream - for example on a smart-card device.
 */
public class MerlinDevice extends Merlin {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(MerlinDevice.class);
    private static final boolean DO_DEBUG = LOG.isDebugEnabled();

    
    @Override
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
        String keyStorePassword = properties.getProperty(KEYSTORE_PASSWORD, "security");
        if (keyStorePassword != null) {
            keyStorePassword = keyStorePassword.trim();
        }
        String keyStoreType = properties.getProperty(KEYSTORE_TYPE, KeyStore.getDefaultType());
        if (keyStoreType != null) {
            keyStoreType = keyStoreType.trim();
        }
        if (keyStoreLocation != null) {
            keyStoreLocation = keyStoreLocation.trim();
            InputStream is = loadInputStream(loader, keyStoreLocation);

            try {
                keystore = load(is, keyStorePassword, provider, keyStoreType);
                if (DO_DEBUG) {
                    LOG.debug(
                        "The KeyStore " + keyStoreLocation + " of type " + keyStoreType 
                        + " has been loaded"
                    );
                }
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } else {
            keystore = load(null, keyStorePassword, provider, keyStoreType);
        }
        
        //
        // Load the TrustStore
        //
        String trustStorePassword = properties.getProperty(TRUSTSTORE_PASSWORD, "changeit");
        if (trustStorePassword != null) {
            trustStorePassword = trustStorePassword.trim();
        }
        String trustStoreType = properties.getProperty(TRUSTSTORE_TYPE, KeyStore.getDefaultType());
        if (trustStoreType != null) {
            trustStoreType = trustStoreType.trim();
        }
        String loadCacerts = properties.getProperty(LOAD_CA_CERTS, "false");
        if (loadCacerts != null) {
            loadCacerts = loadCacerts.trim();
        }
        String trustStoreLocation = properties.getProperty(TRUSTSTORE_FILE);
        if (trustStoreLocation != null) {
            trustStoreLocation = trustStoreLocation.trim();
            InputStream is = loadInputStream(loader, trustStoreLocation);

            try {
                truststore = load(is, trustStorePassword, provider, trustStoreType);
                if (DO_DEBUG) {
                    LOG.debug(
                        "The TrustStore " + trustStoreLocation + " of type " + trustStoreType 
                        + " has been loaded"
                    );
                }
                loadCACerts = false;
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } else if (Boolean.valueOf(loadCacerts).booleanValue()) {
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
        } else {
            truststore = load(null, trustStorePassword, provider, trustStoreType);
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

}
