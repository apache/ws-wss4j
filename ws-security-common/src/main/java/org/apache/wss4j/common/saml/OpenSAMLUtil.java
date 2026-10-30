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

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceConfigurationError;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;

import net.shibboleth.shared.xml.impl.BasicParserPool;
import net.shibboleth.shared.xml.ParserPool;

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.provider.MapBasedConfiguration;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLConfigurationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.config.SAMLConfiguration;
import org.opensaml.xmlsec.config.DecryptionParserPool;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.SignerProvider;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;

/**
 * Class OpenSAMLUtil provides static helper methods for the OpenSaml library
 */
public final class OpenSAMLUtil {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(OpenSAMLUtil.class);

    private static final String DEFER_NODE_EXPANSION_FEATURE =
        "http://apache.org/xml/features/dom/defer-node-expansion";

    private static XMLObjectProviderRegistry providerRegistry;
    private static XMLObjectBuilderFactory builderFactory;
    private static MarshallerFactory marshallerFactory;
    private static UnmarshallerFactory unmarshallerFactory;
    private static boolean samlEngineInitialized = false;

    private OpenSAMLUtil() {
        // Complete
    }

    /**
     * Initialise the SAML library
     */
    public static synchronized void initSamlEngine() {
        initSamlEngine(true);
    }

    public static synchronized void initSamlEngine(boolean includeXacml) {
        if (!samlEngineInitialized) {
            LOG.debug("Initializing the opensaml2 library...");
            WSProviderConfig.init();

            try {
                XMLObjectProviderRegistry existingRegistry = getExistingProviderRegistry();
                if (existingRegistry != null) {
                    // OpenSAML has already been initialized (e.g. via InitializationService), so keep the
                    // existing configuration, including the parser pools
                    LOG.debug("Using the existing OpenSAML configuration");
                    providerRegistry = existingRegistry;
                } else {
                    ConfigurationService.setConfiguration(new MapBasedConfiguration());

                    providerRegistry = new XMLObjectProviderRegistry();
                    ConfigurationService.register(XMLObjectProviderRegistry.class, providerRegistry);
                }

                // Always load the object providers, as an existing initialization may be partial (e.g. in OSGi,
                // InitializationService only finds the initializers that are visible to the context classloader)
                OpenSAMLBootstrap.bootstrap(includeXacml);

                if (ConfigurationService.get(SAMLConfiguration.class) == null) {
                    ConfigurationService.register(SAMLConfiguration.class, new SAMLConfiguration());
                }

                builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
                marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
                unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

                try {
                    if (providerRegistry.getParserPool() == null) {
                        configureParserPool();
                    }

                    // used by org.opensaml.saml.saml2.encryption.Decrypter
                    if (ConfigurationService.get(DecryptionParserPool.class) == null) {
                        ConfigurationService.register(DecryptionParserPool.class,
                                                      new DecryptionParserPool(createDecryptionParserPool()));
                    }
                } catch (Throwable t) {
                    LOG.warn("Unable to bootstrap the parser pool part of the opensaml library "
                             + "- some SAML operations may fail", t);
                }

                samlEngineInitialized = true;
                LOG.debug("opensaml3 library bootstrap complete");
            } catch (XMLConfigurationException ex) {
                LOG.error("Unable to bootstrap the opensaml3 library - all SAML operations will fail", ex);
            }
        }
    }

    private static XMLObjectProviderRegistry getExistingProviderRegistry() {
        try {
            return ConfigurationService.get(XMLObjectProviderRegistry.class);
        } catch (ServiceConfigurationError e) {
            // The lookup of a Configuration implementation via the ServiceLoader failed (e.g. due to
            // classloader visibility in OSGi), so treat OpenSAML as not initialized
            LOG.debug("Unable to look up an existing OpenSAML configuration", e);
            return null;
        }
    }

    private static void configureParserPool() throws Throwable {
        BasicParserPool pp = new BasicParserPool();
        pp.setMaxPoolSize(50);
        pp.initialize();
        providerRegistry.setParserPool(pp);
    }

    /**
     * Create a ParserPool for decryption, configured in the same way as OpenSAML's
     * DecryptionParserPoolInitializer.
     */
    private static ParserPool createDecryptionParserPool() {
        try {
            BasicParserPool pp = new BasicParserPool();
            pp.setMaxPoolSize(50);

            // Start with the default (hardened) features, and add the decryption-specific feature. The
            // hardening features are set explicitly so that they cannot be lost when the features are replaced.
            Map<String, Boolean> features = new HashMap<>(pp.getBuilderFeatures());
            features.put(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
            features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
            features.put(DEFER_NODE_EXPANSION_FEATURE, Boolean.FALSE);
            pp.setBuilderFeatures(features);

            pp.initialize();
            return pp;
        } catch (Throwable t) {
            // e.g. the XML parser does not support the feature - fall back to the default parser pool
            LOG.warn("Unable to create a decryption-specific parser pool, using the default parser pool instead", t);
            return getParserPool();
        }
    }

    /**
     * Get the configured ParserPool.
     *
     * @return the configured ParserPool
     */
    public static ParserPool getParserPool() {
        return providerRegistry.getParserPool();
    }

    /**
     * Convert a SAML Assertion from a DOM Element to an XMLObject
     *
     * @param root of type Element
     * @return XMLObject
     * @throws WSSecurityException
     */
    public static XMLObject fromDom(Element root) throws WSSecurityException {
        if (root == null) {
            LOG.debug("Attempting to unmarshal a null element!");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                          new Object[] {"Error unmarshalling a SAML assertion"});
        }
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(root);
        if (unmarshaller == null) {
            LOG.debug("Unable to find an unmarshaller for element: " + root.getLocalName());
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                          new Object[] {"Error unmarshalling a SAML assertion"});
        }
        try {
            return unmarshaller.unmarshall(root);
        } catch (UnmarshallingException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                                          new Object[] {"Error unmarshalling a SAML assertion"});
        }
    }

    /**
     * An XMLObject can only have one parent. Return the given XMLObject if it has no parent,
     * otherwise return a copy of it, for example if the same bean is used to create more than
     * one SAML assertion. Elements without a registered unmarshaller are copied using the
     * default provider (XSAny).
     *
     * @param xmlObject the XMLObject to add to a new parent
     * @return the XMLObject, or a copy of it if it already has a parent
     * @throws WSSecurityException if the XMLObject could not be copied
     */
    public static XMLObject cloneIfParented(XMLObject xmlObject) throws WSSecurityException {
        if (xmlObject.getParent() == null) {
            return xmlObject;
        }
        try {
            Element element = XMLObjectSupport.marshall(xmlObject);
            UnmarshallerFactory factory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = factory.getUnmarshaller(element);
            if (unmarshaller == null) {
                unmarshaller = factory.getUnmarshaller(XMLObjectProviderRegistrySupport.getDefaultProviderQName());
            }
            XMLObject clone = unmarshaller.unmarshall(element);
            // Detach the copy from the DOM of the original object
            clone.releaseDOM();
            clone.releaseChildrenDOM(true);
            return clone;
        } catch (MarshallingException | UnmarshallingException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                                          new Object[] {"Error copying an XMLObject"});
        }
    }

    /**
     * Convert a SAML Assertion from a XMLObject to a DOM Element
     *
     * @param xmlObject of type XMLObject
     * @param doc of type Document
     * @return Element
     * @throws WSSecurityException
     */
    public static Element toDom(
        XMLObject xmlObject,
        Document doc
    ) throws WSSecurityException {
        return toDom(xmlObject, doc, true);
    }

    /**
     * Convert a SAML Assertion from a XMLObject to a DOM Element
     *
     * @param xmlObject of type XMLObject
     * @param doc of type Document
     * @param signObject whether to sign the XMLObject during marshalling
     * @return Element
     * @throws WSSecurityException
     */
    public static Element toDom(
        XMLObject xmlObject,
        Document doc,
        boolean signObject
    ) throws WSSecurityException {
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        Element element = null;
        DocumentFragment frag = doc == null ? null : doc.createDocumentFragment();
        try {
            if (frag != null) {
                while (doc.getFirstChild() != null) {
                    frag.appendChild(doc.removeChild(doc.getFirstChild()));
                }
            }
            try {
                if (doc == null) {
                    element = marshaller.marshall(xmlObject);
                } else {
                    element = marshaller.marshall(xmlObject, doc);
                }
            } catch (MarshallingException ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                                              new Object[] {"Error marshalling a SAML assertion"});
            }

            if (signObject) {
                signXMLObject(xmlObject);
            }
        } finally {
            if (frag != null) {
                while (doc.getFirstChild() != null) {
                    doc.removeChild(doc.getFirstChild());
                }
                doc.appendChild(frag);
            }
        }
        return element;
    }

    private static void signXMLObject(XMLObject xmlObject) throws WSSecurityException {
        if (xmlObject instanceof org.opensaml.saml.saml1.core.Response) {
            org.opensaml.saml.saml1.core.Response response =
                    (org.opensaml.saml.saml1.core.Response)xmlObject;

            // Sign any Assertions
            if (response.getAssertions() != null) {
                for (org.opensaml.saml.saml1.core.Assertion assertion : response.getAssertions()) {
                    signObject(assertion.getSignature());
                }
            }

            signObject(response.getSignature());
        } else if (xmlObject instanceof org.opensaml.saml.saml2.core.Response) {
            org.opensaml.saml.saml2.core.Response response =
                    (org.opensaml.saml.saml2.core.Response)xmlObject;

            // Sign any Assertions
            if (response.getAssertions() != null) {
                for (org.opensaml.saml.saml2.core.Assertion assertion : response.getAssertions()) {
                    signObject(assertion.getSignature());
                }
            }

            signObject(response.getSignature());
        } else if (xmlObject instanceof SignableSAMLObject) {
            signObject(((SignableSAMLObject)xmlObject).getSignature());
        }
    }

    private static void signObject(Signature signature) throws WSSecurityException {
        if (signature != null) {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(SignerProvider.class.getClassLoader());
                Signer.signObject(signature);
            } catch (SignatureException ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                                              new Object[] {"Error signing a SAML assertion"});
            } finally {
                Thread.currentThread().setContextClassLoader(loader);
            }
        }
    }

    /**
     * Method buildSignature ...
     *
     * @return Signature
     */
    @SuppressWarnings("unchecked")
    public static Signature buildSignature() {
        QName qName = Signature.DEFAULT_ELEMENT_NAME;
        XMLObjectBuilder<Signature> builder =
            (XMLObjectBuilder<Signature>)builderFactory.getBuilder(qName);
        if (builder == null) {
            LOG.error(
                "Unable to retrieve builder for object QName "
                + qName
            );
            return null;
        }
        return
            builder.buildObject(
                 qName.getNamespaceURI(), qName.getLocalPart(), qName.getPrefix()
             );
    }

    /**
     * Method isMethodSenderVouches ...
     *
     * @param confirmMethod of type String
     * @return boolean
     */
    public static boolean isMethodSenderVouches(String confirmMethod) {
        return
            confirmMethod != null && confirmMethod.startsWith("urn:oasis:names:tc:SAML:")
                && confirmMethod.endsWith(":cm:sender-vouches");
    }

    /**
     * Method isMethodHolderOfKey ...
     *
     * @param confirmMethod of type String
     * @return boolean
     */
    public static boolean isMethodHolderOfKey(String confirmMethod) {
        return
            confirmMethod != null && confirmMethod.startsWith("urn:oasis:names:tc:SAML:")
                && confirmMethod.endsWith(":cm:holder-of-key");
    }

}
