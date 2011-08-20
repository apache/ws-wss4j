/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xmlsecurity.ns.configuration.PropertiesType;
import org.xmlsecurity.ns.configuration.PropertyType;

import java.util.List;
import java.util.Properties;

/**
 * Configuration Properties
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ConfigurationProperties {

    private static final transient Log logger = LogFactory.getLog(ConfigurationProperties.class);

    private static Properties properties;

    private ConfigurationProperties() {
        super();
    }

    protected static void init(PropertiesType propertiesType) throws Exception {
        properties = new Properties();
        List<PropertyType> handlerList = propertiesType.getProperty();
        for (int i = 0; i < handlerList.size(); i++) {
            PropertyType propertyType = handlerList.get(i);
            properties.setProperty(propertyType.getNAME(), propertyType.getVAL());
        }
    }

    public static String getProperty(String key) {
        return properties.getProperty(key);
    }
}
