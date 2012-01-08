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
package org.swssf.xmlsec.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.xmlsec.ext.XMLSecurityUtils;
import org.xmlsecurity.ns.configuration.HandlerType;
import org.xmlsecurity.ns.configuration.SecurityHeaderHandlersType;

import javax.xml.namespace.QName;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Security-header handler mapper
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityHeaderHandlerMapper {

    private static final transient Log logger = LogFactory.getLog(SecurityHeaderHandlerMapper.class);

    private static Map<QName, HandlerType> handlerMap;
    private static Map<QName, Class> handlerClassMap;

    private SecurityHeaderHandlerMapper() {
    }

    protected synchronized static void init(SecurityHeaderHandlersType securityHeaderHandlersType) throws Exception {
        handlerMap = new HashMap<QName, HandlerType>();
        handlerClassMap = new HashMap<QName, Class>();
        List<HandlerType> handlerList = securityHeaderHandlersType.getHandler();
        for (int i = 0; i < handlerList.size(); i++) {
            HandlerType handlerType = handlerList.get(i);
            QName qName = new QName(handlerType.getURI(), handlerType.getNAME());
            handlerMap.put(qName, handlerType);
            handlerClassMap.put(qName, XMLSecurityUtils.loadClass(handlerType.getJAVACLASS()));
        }
    }

    public static Class getSecurityHeaderHandler(QName name) {
        Class clazz = handlerClassMap.get(name);
        return clazz;
    }

    public static HandlerType getHandlerMapping(QName name) {
        return handlerMap.get(name);
    }
}
