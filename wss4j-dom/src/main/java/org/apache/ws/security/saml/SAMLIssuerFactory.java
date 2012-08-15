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

package org.apache.ws.security.saml;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Loader;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.Properties;

/**
 * CryptoFactory.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public abstract class SAMLIssuerFactory {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SAMLIssuerFactory.class);
    private static final Class<? extends SAMLIssuer> DEFAULT_SAML_CLASS = 
        org.apache.ws.security.saml.SAMLIssuerImpl.class;

    /**
     * getInstance
     * <p/>
     * Returns an instance of SAMLIssuer. This method uses the file
     * <code>saml.properties</code> to determine which implementation to
     * use. Thus the property <code>org.apache.ws.security.saml.issuerClass</code>
     * must define the classname of the SAMLIssuer implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the  SAMLIssuer implementation. The file
     * <code>saml.properties</code> is loaded with the
     * <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @return The SAMLIssuer implementation was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static SAMLIssuer getInstance() throws WSSecurityException {
        return getInstance("saml.properties");
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of SAMLIssuer. The properties are handed over the the SAMLIssuer
     * implementation. The properties can be <code>null</code>. It is dependent on the
     * SAMLIssuer implementation how the initialization is done in this case.
     * <p/>
     *
     * @param samlClass     This is the SAMLIssuer implementation class. No default is
     *                      provided here.
     * @param properties    The Properties that are forwarded to the SAMLIssuer implementation.
     *                      These properties are dependent on the SAMLIssuer implementation
     * @return The SAMLIssuer implementation or null if no samlClassName was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static SAMLIssuer getInstance(
        Class<? extends SAMLIssuer> samlClass,
        Properties properties
    ) throws WSSecurityException {
        return loadClass(samlClass, properties);
    }

    /**
     * getInstance
     * <p/>
     * Returns an instance of SAMLIssuer. This method uses the specified filename
     * to load a property file. This file shall use the property
     * <code>org.apache.ws.security.saml.issuerClass</code>
     * to define the classname of the SAMLIssuer implementation. The file
     * may contain other property definitions as well. These properties are
     * handed over to the SAMLIssuer implementation. The specified file
     * is loaded with the <code>Loader.getResource()</code> method.
     * <p/>
     *
     * @param propFilename The name of the property file to load
     * @return The SAMLIssuer implementation that was defined
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    public static SAMLIssuer getInstance(String propFilename) throws WSSecurityException {
        Properties properties = getProperties(propFilename);
        String samlClassName = 
            properties.getProperty("org.apache.ws.security.saml.issuerClass");
        Class<? extends SAMLIssuer> samlIssuerClass = null;
        if (samlClassName == null 
            || samlClassName.equals("org.apache.ws.security.saml.SAMLIssuerImpl")) {
            samlIssuerClass = DEFAULT_SAML_CLASS;
        } else {
            try {
                // instruct the class loader to load the crypto implementation
                samlIssuerClass = Loader.loadClass(samlClassName, SAMLIssuer.class);
            } catch (ClassNotFoundException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ex.getMessage(), ex);
                }
                throw new WSSecurityException(samlClassName + " Not Found", ex);
            }
        }

        return loadClass(samlIssuerClass, properties);
    }

    private static SAMLIssuer loadClass(
        Class<? extends SAMLIssuer> samlIssuerClass, 
        Properties properties
    ) throws WSSecurityException {
        SAMLIssuer samlIssuer = null;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using Crypto Engine [" + samlIssuerClass + "]");
        }
        try {
            Class<?>[] classes = new Class<?>[]{Properties.class};
            Constructor<? extends SAMLIssuer> c = samlIssuerClass.getConstructor(classes);
            samlIssuer = c.newInstance(new Object[]{properties});
            return samlIssuer;
        } catch (java.lang.Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getMessage(), ex);
            }
            throw new WSSecurityException(samlIssuerClass.getName() + " cannot create instance", ex);
        }
    }

    /**
     * Gets the properties for SAML issuer.
     * The functions loads the property file via
     * {@link Loader.getResource(String)}, thus the property file
     * should be accessible via the classpath
     *
     * @param propFilename the properties file to load
     * @return a <code>Properties</code> object loaded from the filename
     * @throws WSSecurityException if there is an error in loading the crypto properties
     */
    private static Properties getProperties(String propFilename) throws WSSecurityException {
        Properties properties = new Properties();
        try {
            URL url = Loader.getResource(propFilename);
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
