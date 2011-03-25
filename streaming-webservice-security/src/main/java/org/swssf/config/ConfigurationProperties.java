/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
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
 * @author $Author: $
 * @version $Revision: $ $Date: $
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
