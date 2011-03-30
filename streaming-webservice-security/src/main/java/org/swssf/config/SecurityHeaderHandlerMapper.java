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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.ext.Utils;
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
        if (handlerType == null) {
            logger.warn("No handler for " + name + " found");
            return null;
        }
        String javaClass = handlerType.getJAVACLASS();
        if (javaClass == null) {
            logger.warn("No handler for " + name + " found");
            return null;
        }
        try {
            return Utils.loadClass(javaClass);
        } catch (ClassNotFoundException e) {
            logger.warn("No handler for " + name + " found: " + e.getMessage());
        }
        return null;
    }
}
