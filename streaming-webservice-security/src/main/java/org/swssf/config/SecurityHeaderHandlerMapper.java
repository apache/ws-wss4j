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
import org.xmlsecurity.ns.configuration.HandlerType;
import org.xmlsecurity.ns.configuration.SecurityHeaderHandlersType;

import javax.xml.namespace.QName;
import java.util.HashMap;
import java.util.List;

/**
 * Security-header handler mapper
 *
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class SecurityHeaderHandlerMapper {

    private static final transient Log logger = LogFactory.getLog(SecurityHeaderHandlerMapper.class);

    private static HashMap<QName, HandlerType> handlerMap;

    private SecurityHeaderHandlerMapper() {
    }

    protected static void init(SecurityHeaderHandlersType securityHeaderHandlersType) throws Exception {
        handlerMap = new HashMap<QName, HandlerType>();
        List<HandlerType> handlerList = securityHeaderHandlersType.getHandler();
        for (int i = 0; i < handlerList.size(); i++) {
            HandlerType handlerType = handlerList.get(i);
            handlerMap.put(new QName(handlerType.getURI(), handlerType.getNAME()), handlerType);
        }
    }

    public static Class getSecurityHeaderHandler(QName name) {
        HandlerType handlerType = handlerMap.get(name);
        String javaClass = handlerType.getJAVACLASS();
        if (javaClass == null) {
            return null;
        }
        try {
            return Thread.currentThread().getContextClassLoader().loadClass(javaClass);
        } catch (ClassNotFoundException e) {
            logger.warn("No handler for " + name + " found: " + e.getMessage());
        }
        return null;
    }
}
