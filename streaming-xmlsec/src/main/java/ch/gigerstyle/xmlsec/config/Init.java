package ch.gigerstyle.xmlsec.config;

import ch.gigerstyle.xmlsec.ext.XMLSecurityException;
import org.xmlsecurity.ns.configuration.ConfigurationType;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.net.URL;

/**
 * User: giger
 * Date: May 15, 2010
 * Time: 1:06:42 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class Init {

    private static boolean initialized = false;

    @SuppressWarnings("unchecked")
    //todo init from url
    public synchronized static void init(URL url) throws XMLSecurityException {
        if (!initialized) {
            try {
                JAXBContext jaxbContext = JAXBContext.newInstance("org.xmlsecurity.ns.configuration");
                final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Schema schema = schemaFactory.newSchema(Init.class.getClassLoader().getResource("security-config.xsd"));
                unmarshaller.setSchema(schema);
                JAXBElement<ConfigurationType> configurationTypeJAXBElement = (JAXBElement<ConfigurationType>) unmarshaller.unmarshal(Init.class.getClassLoader().getResourceAsStream("security-config.xml"));

                JCEAlgorithmMapper.init(configurationTypeJAXBElement.getValue().getJCEAlgorithmMappings());

            } catch (Exception e) {
                throw new XMLSecurityException(e.getMessage(), e);
            }
            initialized = true;
        }
    }
}
