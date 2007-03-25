/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.components.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Loader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

/**
 * Created by IntelliJ IDEA.
 * User: dims
 * Date: Sep 15, 2005
 * Time: 9:50:40 AM
 * To change this template use File | Settings | File Templates.
 */
public abstract class AbstractCrypto extends CryptoBase {
    private static Log log = LogFactory.getLog(AbstractCrypto.class);
    protected static CertificateFactory certFact;
    protected Properties properties = null;
    static String SKI_OID = "2.5.29.14";
    
    /**
     * Constructor
     *
     * @param properties
     */
    public AbstractCrypto(Properties properties) throws CredentialException, IOException {
    	this(properties,AbstractCrypto.class.getClassLoader());
    }

    /**
     * This allows providing a custom class loader to load the resources, etc
     * @param properties
     * @param loader
     * @throws CredentialException
     * @throws IOException
     */
    public AbstractCrypto(Properties properties, ClassLoader loader) throws CredentialException, IOException {
        this.properties = properties;
        String location = this.properties.getProperty("org.apache.ws.security.crypto.merlin.file");


		InputStream is = null;

		java.net.URL url = Loader.getResource(loader, location);

		if(url != null) {

			is =  url.openStream();

		} else {

			is = new java.io.FileInputStream(location);

		}


        /**
         * If we don't find it, then look on the file system.
         */
        if (is == null) {
            try {
                is = new FileInputStream(location);
            } catch (Exception e) {
                throw new CredentialException(3, "proxyNotFound", new Object[]{location});
            }
        }

        /**
         * Load the keystore
         */
        try {
            load(is);
        } finally {
            is.close();
        }
    }

    protected String
    getCryptoProvider() {
        return properties.getProperty("org.apache.ws.security.crypto.merlin.cert.provider");
    }

    /**
     * Retrieves the alias name of the default certificate which has been
     * specified as a property. This should be the certificate that is used for
     * signature and encryption. This alias corresponds to the certificate that
     * should be used whenever KeyInfo is not poresent in a signed or
     * an encrypted message. May return null.
     *
     * @return alias name of the default X509 certificate
     */
    public String getDefaultX509Alias() {
        if (properties == null) {
            return null;
        }
        return properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.alias");
    }


    /**
     * Loads the the keystore from an <code>InputStream </code>.
     * <p/>
     *
     * @param input <code>InputStream</code> to read from
     * @throws CredentialException
     */
    public void load(InputStream input) throws CredentialException {
        if (input == null) {
            throw new IllegalArgumentException("input stream cannot be null");
        }
        try {
            String provider = properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.provider");
            if (provider == null || provider.length() == 0) {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()));
            } else {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()), provider);
            }
            String password =
                    properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.password",
                            "security");
            keystore.load(input, (password == null || password.length() == 0) ? new char[0] : password.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
            throw new CredentialException(3, "ioError00", e);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new CredentialException(3, "secError00", e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CredentialException(-1, "error00", e);
        }
    }
}
