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

package org.apache.wss4j.common.saml;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLConfigurator;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;

/**
 * This class intializes the Opensaml library. It is necessary to override DefaultBootstrap
 * to avoid instantiating Velocity, which we do not need in WSS4J.
 */
public final class OpenSAMLBootstrap extends DefaultBootstrap {
    
    /** List of default XMLTooling configuration files. */
    private static final String[] xmlToolingConfigs = { 
        "/default-config.xml", 
        "/schema-config.xml", 
        "/signature-config.xml",
        "/signature-validation-config.xml", 
        "/encryption-config.xml", 
        "/encryption-validation-config.xml",
        "/soap11-config.xml", 
        "/wsfed11-protocol-config.xml",
        "/saml1-assertion-config.xml", 
        "/saml1-protocol-config.xml",
        "/saml1-core-validation-config.xml", 
        "/saml2-assertion-config.xml", 
        "/saml2-protocol-config.xml",
        "/saml2-core-validation-config.xml", 
        "/saml1-metadata-config.xml", 
        "/saml2-metadata-config.xml",
        "/saml2-metadata-validation-config.xml", 
        "/saml2-metadata-attr-config.xml",
        "/saml2-metadata-idp-discovery-config.xml",
        "/saml2-metadata-ui-config.xml",
        "/saml2-protocol-thirdparty-config.xml",
        "/saml2-metadata-query-config.xml", 
        "/saml2-assertion-delegation-restriction-config.xml",    
        "/saml2-ecp-config.xml",
        "/saml2-xacml2-profile.xml",
        "/xacml10-saml2-profile-config.xml",
        "/xacml11-saml2-profile-config.xml",
        "/xacml20-context-config.xml",
        "/xacml20-policy-config.xml",
        "/xacml2-saml2-profile-config.xml",
        "/xacml3-saml2-profile-config.xml",    
        "/wsaddressing-config.xml",
        "/wssecurity-config.xml",
    };
    
    private OpenSAMLBootstrap() {
        // complete
    }
    
    /**
     * Initializes the OpenSAML library, loading default configurations.
     * 
     * @throws ConfigurationException thrown if there is a problem initializing the OpenSAML library
     */
    public static synchronized void bootstrap() throws ConfigurationException {
        initializeXMLSecurity();

        initializeXMLTooling(xmlToolingConfigs);

        initializeArtifactBuilderFactories();

        initializeGlobalSecurityConfiguration();
        
        initializeParserPool();
    }

    
    protected static void initializeXMLTooling(String[] providerConfigs) throws ConfigurationException {
        XMLConfigurator configurator = new XMLConfigurator();
        for (String config : providerConfigs) {
            //most are found in the Configuration.class classloader
            InputStream ins = Configuration.class.getResourceAsStream(config);
            if (ins == null) {
                //some are from us
                ins = OpenSAMLBootstrap.class.getResourceAsStream(config);
            }
            if (ins != null) {
                configurator.load(ins);
                try {
                    ins.close();
                } catch (java.io.IOException ex) { //NOPMD
                    // complete
                }
            }
        }
    }
    
    protected static void initializeParserPool() throws ConfigurationException {
        StaticBasicParserPool pp = new StaticBasicParserPool();
        pp.setMaxPoolSize(50);
        
        Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", true);
        pp.setBuilderFeatures(features);
        pp.setExpandEntityReferences(false);
        
        try {
            pp.initialize();
        } catch (XMLParserException e) {
            throw new ConfigurationException("Error initializing parser pool", e);
        }
        Configuration.setParserPool(pp);
    }
}
