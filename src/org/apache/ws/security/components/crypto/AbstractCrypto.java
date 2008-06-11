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
import org.apache.ws.security.util.Loader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Properties;

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
        if (this.properties == null) {
            return;
        }
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
            String provider = properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.provider");
            String passwd = properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.password","security");
            String type = properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type", KeyStore.getDefaultType());
            this.keystore = load(is, passwd, provider, type);
        } finally {
            is.close();
        }

        /**
         * Load cacerts
         */
        String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
        InputStream cacertsIs = new FileInputStream(cacertsPath);
        try {
            String cacertsPasswd = properties.getProperty("org.apache.ws.security.crypto.merlin.cacerts.password", "changeit");
            this.cacerts = load(cacertsIs, cacertsPasswd, null, KeyStore.getDefaultType());
        } finally {
            cacertsIs.close();
        }
    }


    /**
     * Loads the the keystore from an <code>InputStream </code>.
     * <p/>
     *
     * @param input <code>InputStream</code> to read from
     * @throws CredentialException
     */
    public KeyStore load(InputStream input, String storepass, String provider, String type) throws CredentialException {
        if (input == null) {
            throw new IllegalArgumentException("input stream cannot be null");
        }
        
        KeyStore ks = null;
        
        try {
            if (provider == null || provider.length() == 0) {
                ks = KeyStore.getInstance(type);
            } else {
                ks = KeyStore.getInstance(type, provider);
            }
            
                    
            ks.load(input, (storepass == null || storepass.length() == 0) ? new char[0] : storepass.toCharArray());
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
        return ks;
    }

    
    protected String
    getCryptoProvider() {
        return properties.getProperty("org.apache.ws.security.crypto.merlin.cert.provider");
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
        if (properties == null) {
            return null;
        }
        return properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.alias");
    }
}
