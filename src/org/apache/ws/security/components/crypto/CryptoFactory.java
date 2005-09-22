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

import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.Properties;

/**
 * CryptoFactory.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public abstract class CryptoFactory {
    private static Log log = LogFactory.getLog(CryptoFactory.class);
    private static final String defaultCryptoClassName = "org.apache.ws.security.components.crypto.Merlin";

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. This method uses the file
     * <code>crypto.properties</code> to determine which implementation to
     * use. Thus the property <code>org.apache.ws.security.crypto.provider</code>
     * must define the classname of the Crypto implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the  Crypto implementation. The file
     * <code>crypto.properties</code> is loaded with the
     * <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @return The cyrpto implementation was defined
     */
    public static Crypto getInstance() {
        return getInstance("crypto.properties");
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. The properties are handed over the the crypto
     * implementation. The porperties can be <code>null</code>. It is depenend on the
     * Crypto implementation how the initialization is done in this case.
     * <p/>
     *
     * @param cryptoClassName This is the crypto implementation class. No default is
     *                        provided here.
     * @param properties      The Properties that are forwarded to the crypto implementaion.
     *                        These properties are dependend on the crypto implementatin
     * @return The cyrpto implementation or null if no cryptoClassName was defined
     */
    public static Crypto getInstance(String cryptoClassName, Properties properties) {
        return loadClass(cryptoClassName, properties);
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. This method uses the specifed filename
     * to load a property file. This file shall use the property
     * <code>org.apache.ws.security.crypto.provider</code>
     * to define the classname of the Crypto implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the Crypto implementation. The specified file
     * is loaded with the <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @param propFilename The name of the property file to load
     * @return The cyrpto implementation that was defined
     */
    public static Crypto getInstance(String propFilename) {
        Properties properties = null;
        String cryptoClassName = null;

        // cryptoClassName = System.getProperty("org.apache.ws.security.crypto.provider");
        if ((cryptoClassName == null) || (cryptoClassName.length() == 0)) {
            properties = getProperties(propFilename);
            // use the default Crypto implementation
            cryptoClassName = properties.getProperty("org.apache.ws.security.crypto.provider",
                    defaultCryptoClassName);
        }
        return loadClass(cryptoClassName, properties);
    }

    private static Crypto loadClass(String cryptoClassName, Properties properties) {
        Class cryptogenClass = null;
        Crypto crypto = null;
        try {
            // instruct the class loader to load the crypto implementation
            cryptogenClass = Loader.loadClass(cryptoClassName);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(cryptoClassName + " Not Found");
        }
        log.debug("Using Crypto Engine [" + cryptoClassName + "]");
        try {
            Class[] classes = new Class[]{Properties.class};
            Constructor c = cryptogenClass.getConstructor(classes);
            crypto = (Crypto) c.newInstance(new Object[]{properties});
            return crypto;
        } catch (java.lang.Exception e) {
            e.printStackTrace();
            log.error("Unable to instantiate (1): " + cryptoClassName, e);
        }
        try {
            // try to instantiate the Crypto subclass
            crypto = (Crypto) cryptogenClass.newInstance();
            return crypto;
        } catch (java.lang.Exception e) {
            e.printStackTrace();
            log.error("Unable to instantiate (2): " + cryptoClassName, e);
            throw new RuntimeException(cryptoClassName + " cannot create instance");
        }
    }

    /**
     * Gets the properties for crypto.
     * The functions loads the property file via
     * {@link Loader.getResource(String)}, thus the property file
     * should be accesible via the classpath
     *
     * @param propFilename the properties file to load
     * @return a <code>Properties</code> object loaded from the filename
     */
    private static Properties getProperties(String propFilename) {
        Properties properties = new Properties();
        try {
            URL url = Loader.getResource(propFilename);
            properties.load(url.openStream());
        } catch (Exception e) {
            log.debug("Cannot find crypto property file: " + propFilename);
            throw new RuntimeException("CryptoFactory: Cannot load properties: " +
                    propFilename);
        }
        return properties;
    }
}

