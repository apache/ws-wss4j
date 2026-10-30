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

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ServiceLoader;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;

import net.shibboleth.shared.xml.ParserPool;
import net.shibboleth.shared.xml.impl.BasicParserPool;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.Initializer;
import org.opensaml.core.config.provider.MapBasedConfiguration;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.xmlsec.config.DecryptionParserPool;
import org.opensaml.xmlsec.signature.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Some tests for OpenSAMLUtil
 */
public class OpenSAMLUtilTest {

    @BeforeEach
    public void resetOpenSAML() throws Exception {
        // Start each test with neither OpenSAML nor WSS4J initialized
        ConfigurationService.setConfiguration(new MapBasedConfiguration());
        Field initialized = OpenSAMLUtil.class.getDeclaredField("samlEngineInitialized");
        initialized.setAccessible(true);
        initialized.setBoolean(null, false);
    }

    @Test
    public void testInitSamlEngine() throws Exception {
        OpenSAMLUtil.initSamlEngine();

        // https://issues.apache.org/jira/browse/WSS-678 OpenSAML Decrypter initialization failed
        new org.opensaml.saml.saml2.encryption.Decrypter(null, null, null);

        // The decryption parser pool is distinct from the general parser pool
        DecryptionParserPool decryptionParserPool = ConfigurationService.get(DecryptionParserPool.class);
        assertNotNull(decryptionParserPool);
        assertNotSame(OpenSAMLUtil.getParserPool(), decryptionParserPool.getParserPool());
        assertRejectsDoctype(decryptionParserPool.getParserPool());

        assertWss4jConfig();
    }

    // https://issues.apache.org/jira/browse/WSS-697
    @Test
    public void testExistingOpenSAMLConfigurationIsPreserved() throws Exception {
        // Initialize OpenSAML in the same way as InitializationService.initialize(), except for the
        // metrics initializer, as metrics-core is excluded from the WSS4J dependencies
        for (Initializer initializer : ServiceLoader.load(Initializer.class)) {
            if (!initializer.getClass().getName().endsWith(".MetricRegistryInitializer")) {
                initializer.init();
            }
        }

        ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        DecryptionParserPool decryptionParserPool = ConfigurationService.get(DecryptionParserPool.class);
        assertNotNull(parserPool);
        assertNotNull(decryptionParserPool);

        OpenSAMLUtil.initSamlEngine();

        assertSame(parserPool, XMLObjectProviderRegistrySupport.getParserPool());
        assertSame(parserPool, OpenSAMLUtil.getParserPool());
        assertSame(decryptionParserPool, ConfigurationService.get(DecryptionParserPool.class));

        new org.opensaml.saml.saml2.encryption.Decrypter(null, null, null);

        assertWss4jConfig();
    }

    // e.g. in OSGi, InitializationService may only find some of the initializers
    @Test
    public void testPartialOpenSAMLConfiguration() throws Exception {
        XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();
        registry.setParserPool(parserPool);

        OpenSAMLUtil.initSamlEngine();

        assertSame(registry, ConfigurationService.get(XMLObjectProviderRegistry.class));
        assertSame(parserPool, OpenSAMLUtil.getParserPool());
        assertNotNull(XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME));
        assertNotNull(ConfigurationService.get(DecryptionParserPool.class));
        assertWss4jConfig();
    }

    @Test
    public void testDecryptionParserPoolFallback() throws Exception {
        String factoryProperty = DocumentBuilderFactory.class.getName();
        String oldFactory = System.getProperty(factoryProperty);
        System.setProperty(factoryProperty, NoDeferNodeExpansionDocumentBuilderFactory.class.getName());
        try {
            OpenSAMLUtil.initSamlEngine();
        } finally {
            if (oldFactory == null) {
                System.clearProperty(factoryProperty);
            } else {
                System.setProperty(factoryProperty, oldFactory);
            }
        }

        // The XML parser does not support the decryption-specific feature, so the default parser pool is used
        DecryptionParserPool decryptionParserPool = ConfigurationService.get(DecryptionParserPool.class);
        assertNotNull(decryptionParserPool);
        assertSame(OpenSAMLUtil.getParserPool(), decryptionParserPool.getParserPool());
        assertRejectsDoctype(decryptionParserPool.getParserPool());

        new org.opensaml.saml.saml2.encryption.Decrypter(null, null, null);
    }

    private static void assertRejectsDoctype(ParserPool parserPool) {
        String xxe = "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>";
        assertThrows(Exception.class,
            () -> parserPool.parse(new ByteArrayInputStream(xxe.getBytes(StandardCharsets.UTF_8))));
    }

    private static void assertWss4jConfig() {
        assertTrue(XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                   .getUnmarshaller(X509Certificate.DEFAULT_ELEMENT_NAME) instanceof WSS4JXSBase64BinaryUnmarshaller);
        assertNotNull(XMLObjectProviderRegistrySupport.getBuilderFactory()
                      .getBuilder(new QName("urn:oasis:xacml:2.0:saml:assertion:schema:os", "XACMLAuthzDecisionStatement")));
    }

    /**
     * A DocumentBuilderFactory that does not support the "defer-node-expansion" feature
     */
    public static class NoDeferNodeExpansionDocumentBuilderFactory extends DocumentBuilderFactory {
        private final DocumentBuilderFactory delegate = DocumentBuilderFactory.newDefaultInstance();

        @Override
        public void setFeature(String name, boolean value) throws ParserConfigurationException {
            if (name.endsWith("defer-node-expansion")) {
                throw new ParserConfigurationException("Feature not supported: " + name);
            }
            delegate.setFeature(name, value);
        }

        @Override
        public boolean getFeature(String name) throws ParserConfigurationException {
            return delegate.getFeature(name);
        }

        @Override
        public DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
            return delegate.newDocumentBuilder();
        }

        @Override
        public void setAttribute(String name, Object value) {
            delegate.setAttribute(name, value);
        }

        @Override
        public Object getAttribute(String name) {
            return delegate.getAttribute(name);
        }

        @Override
        public void setNamespaceAware(boolean awareness) {
            delegate.setNamespaceAware(awareness);
        }

        @Override
        public void setValidating(boolean validating) {
            delegate.setValidating(validating);
        }

        @Override
        public void setIgnoringElementContentWhitespace(boolean whitespace) {
            delegate.setIgnoringElementContentWhitespace(whitespace);
        }

        @Override
        public void setExpandEntityReferences(boolean expandEntityRef) {
            delegate.setExpandEntityReferences(expandEntityRef);
        }

        @Override
        public void setIgnoringComments(boolean ignoreComments) {
            delegate.setIgnoringComments(ignoreComments);
        }

        @Override
        public void setCoalescing(boolean coalescing) {
            delegate.setCoalescing(coalescing);
        }

        @Override
        public void setSchema(Schema schema) {
            delegate.setSchema(schema);
        }

        @Override
        public void setXIncludeAware(boolean state) {
            delegate.setXIncludeAware(state);
        }
    }

}
