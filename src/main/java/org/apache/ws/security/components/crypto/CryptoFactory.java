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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Loader;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.Map;
import java.util.Properties;

/**
 * CryptoFactory.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public abstract class CryptoFactory {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(CryptoFactory.class);
    private static final Class<? extends Crypto> DEFAULT_CRYPTO_CLASS = 
        org.apache.ws.security.components.crypto.Merlin.class;

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. This method uses the file
     * <code>crypto.properties</code> to determine which implementation to
     * use. Thus the property <code>org.apache.ws.security.crypto.provider</code>
     * must define the classname of the Crypto implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the Crypto implementation. The file
     * <code>crypto.properties</code> is loaded with the
     * <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @return The crypto implementation was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static Crypto getInstance() throws WSSecurityException {
        return getInstance("crypto.properties");
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. The properties are handed over the the crypto
     * implementation. The properties must at least contain the Crypto implementation
     * class name as the value of the property : org.apache.ws.security.crypto.provider
     * <p/>
     *
     * @param properties      The Properties that are forwarded to the crypto implementation 
     *                        and the Crypto impl class name.
     *                        These properties are dependent on the crypto implementation
     * @return The cyrpto implementation or null if no cryptoClassName was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static Crypto getInstance(Properties properties) throws WSSecurityException {
        return getInstance(properties, Loader.getClassLoader(CryptoFactory.class));
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto loaded with the given classloader. 
     * The properties are handed over the the crypto implementation. 
     * The properties must at least contain the Crypto implementation
     * class name as the value of the property : org.apache.ws.security.crypto.provider
     * <p/>
     *
     * @param properties      The Properties that are forwarded to the crypto implementation 
     *                        and the Crypto impl class name.
     *                        These properties are dependent on the crypto implementation
     * @param classLoader   The class loader to use
     * @return The crypto implementation or null if no cryptoClassName was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static Crypto getInstance(
        Properties properties, 
        ClassLoader classLoader
    ) throws WSSecurityException {
        String cryptoClassName = properties.getProperty("org.apache.ws.security.crypto.provider");
        Class<? extends Crypto> cryptoClass = null;
        if (cryptoClassName == null 
            || cryptoClassName.equals("org.apache.ws.security.components.crypto.Merlin")) {
            cryptoClass = DEFAULT_CRYPTO_CLASS;
        } else {
            try {
                // instruct the class loader to load the crypto implementation
                cryptoClass = Loader.loadClass(cryptoClassName, Crypto.class);
            } catch (ClassNotFoundException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ex.getMessage(), ex);
                }
                throw new WSSecurityException(cryptoClassName + " Not Found", ex);
            }
        }
        return loadClass(cryptoClass, properties, classLoader);
    }
    
    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. The supplied map is handed over the the crypto
     * implementation. The map can be <code>null</code>. It is dependent on the
     * Crypto implementation how the initialization is done in this case.
     * <p/>
     *
     * @param cryptoClass     This is the crypto implementation class. No default is
     *                        provided here.
     * @param map             The Maps that is forwarded to the crypto implementation.
     *                        These contents of the map are dependent on the 
     *                        underlying crypto implementation specified in the 
     *                        cryptoClassName parameter.
     * @return The crypto implementation or null if no cryptoClassName was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static Crypto getInstance(
        Class<? extends Crypto> cryptoClass, 
        Map<Object, Object> map
    ) throws WSSecurityException {
        return loadClass(cryptoClass, map, Loader.getClassLoader(CryptoFactory.class));
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of Crypto. This method uses the specified filename
     * to load a property file. This file shall use the property
     * <code>org.apache.ws.security.crypto.provider</code>
     * to define the classname of the Crypto implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the Crypto implementation. The specified file
     * is loaded with the <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @param propFilename The name of the property file to load
     * @return The crypto implementation that was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static Crypto getInstance(String propFilename) throws WSSecurityException {
        return getInstance(propFilename, Loader.getClassLoader(CryptoFactory.class));
    }    
    
    public static Crypto getInstance(
        String propFilename, 
        ClassLoader customClassLoader
    ) throws WSSecurityException {
        Properties properties = getProperties(propFilename, customClassLoader);
        return getInstance(properties, customClassLoader);
    }

    /**
     * This allows loading the classes with a custom class loader  
     * @param cryptoClass
     * @param properties
     * @param loader
     * @return
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    private static Crypto loadClass(
        Class<? extends Crypto> cryptoClass,
        Map<Object, Object> map, 
        ClassLoader loader
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using Crypto Engine [" + cryptoClass + "]");
        }
        try {
            Class<?>[] classes = new Class[]{Map.class, ClassLoader.class};
            Constructor<? extends Crypto> c = cryptoClass.getConstructor(classes);
            return c.newInstance(new Object[] {map, loader});
        } catch (java.lang.Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to instantiate: " + cryptoClass.getName(), e);
            }
            throw new WSSecurityException(cryptoClass + " cannot create instance", e);
        }
    }
    
    /**
     * This allows loading the classes with a custom class loader  
     * @param cryptoClass
     * @param properties
     * @param loader
     * @return
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    private static Crypto loadClass(
        Class<? extends Crypto> cryptoClass, 
        Properties map, 
        ClassLoader loader
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using Crypto Engine [" + cryptoClass + "]");
        }
        try {
            Class<?>[] classes = new Class[]{Properties.class, ClassLoader.class};
            Constructor<? extends Crypto> c = cryptoClass.getConstructor(classes);
            return c.newInstance(new Object[] {map, loader});
        } catch (java.lang.Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to instantiate: " + cryptoClass.getName(), e);
            }
            throw new WSSecurityException(cryptoClass + " cannot create instance", e);
        }
    }
    
    /**
     * This allows loading the resources with a custom class loader
     * @param propFilename
     * @param loader
     * @return
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    private static Properties getProperties(
        String propFilename, 
        ClassLoader loader
    ) throws WSSecurityException {
        Properties properties = new Properties();
        try {
            URL url = Loader.getResource(loader, propFilename);
            if (url == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, 
                    "resourceNotFound",
                    new Object[]{propFilename}
                );
            }
            properties.load(url.openStream());
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cannot find resource: " + propFilename, e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "resourceNotFound",
                new Object[]{propFilename},
                e
            );
        }
        return properties;
    }

}

