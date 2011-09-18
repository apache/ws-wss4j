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
package org.swssf.config;

import org.swssf.ext.WSSConfigurationException;
import org.swssf.ext.WSSecurityException;
import org.xmlsecurity.ns.configuration.ConfigurationType;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.net.URL;

/**
 * Class to load the algorithms-mappings from a configuration file.
 * After the initialization the mapping is available through the JCEAlgorithmMapper
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class Init {

    private static String initialized = null;

    @SuppressWarnings("unchecked")
    public synchronized static void init(URL url) throws WSSecurityException {
        if (initialized == null || (url != null && !url.toExternalForm().equals(initialized))) {
            try {
                JAXBContext jaxbContext = JAXBContext.newInstance("org.xmlsecurity.ns.configuration");
                final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Schema schema = schemaFactory.newSchema(Init.class.getClassLoader().getResource("security-config.xsd"));
                unmarshaller.setSchema(schema);
                JAXBElement<ConfigurationType> configurationTypeJAXBElement;
                if (url != null) {
                    configurationTypeJAXBElement = (JAXBElement<ConfigurationType>) unmarshaller.unmarshal(url);
                } else {
                    configurationTypeJAXBElement = (JAXBElement<ConfigurationType>) unmarshaller.unmarshal(Init.class.getClassLoader().getResourceAsStream("security-config.xml"));
                }

                ConfigurationProperties.init(configurationTypeJAXBElement.getValue().getProperties());
                SecurityHeaderHandlerMapper.init(configurationTypeJAXBElement.getValue().getSecurityHeaderHandlers());
                JCEAlgorithmMapper.init(configurationTypeJAXBElement.getValue().getJCEAlgorithmMappings());
                TransformerAlgorithmMapper.init(configurationTypeJAXBElement.getValue().getTransformAlgorithms());

            } catch (Exception e) {
                throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, null, e);
            }
            initialized = "security-config.xml";
        }
    }
}
