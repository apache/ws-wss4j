/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
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
                throw new WSSConfigurationException(WSSecurityException.FAILURE, null, e);
            }
            initialized = "security-config.xml";
        }
    }
}
