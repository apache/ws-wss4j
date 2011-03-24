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

    private static boolean initialized = false;

    @SuppressWarnings("unchecked")
    //todo init from url
    public synchronized static void init(URL url) throws WSSecurityException {
        if (!initialized) {
            try {
                JAXBContext jaxbContext = JAXBContext.newInstance("org.xmlsecurity.ns.configuration");
                final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Schema schema = schemaFactory.newSchema(Init.class.getClassLoader().getResource("security-config.xsd"));
                unmarshaller.setSchema(schema);
                JAXBElement<ConfigurationType> configurationTypeJAXBElement = (JAXBElement<ConfigurationType>) unmarshaller.unmarshal(Init.class.getClassLoader().getResourceAsStream("security-config.xml"));

                JCEAlgorithmMapper.init(configurationTypeJAXBElement.getValue().getJCEAlgorithmMappings());
                SecurityHeaderHandlerMapper.init(configurationTypeJAXBElement.getValue().getSecurityHeaderHandlers());

            } catch (Exception e) {
                throw new WSSecurityException(e.getMessage(), e);
            }
            initialized = true;
        }
    }
}
