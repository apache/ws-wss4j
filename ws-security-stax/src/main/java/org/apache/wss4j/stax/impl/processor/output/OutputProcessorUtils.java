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
package org.apache.wss4j.stax.impl.processor.output;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.SecurityHeaderOrder;
import org.apache.xml.security.stax.ext.OutboundSecurityContext;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

public final class OutputProcessorUtils {

    private OutputProcessorUtils() {
        // complete
    }

    public static void updateSecurityHeaderOrder(
            OutputProcessorChain outputProcessorChain, QName headerElementName,
            XMLSecurityConstants.Action action, boolean onTop) {

        final OutboundSecurityContext securityContext = outputProcessorChain.getSecurityContext();

        Map<Object, SecurePart> dynamicSecureParts = securityContext.getAsMap(WSSConstants.ENCRYPTION_PARTS);
        boolean encrypted = false;
        if (dynamicSecureParts != null) {
            encrypted = dynamicSecureParts.containsKey(headerElementName);
        }

        List<SecurityHeaderOrder> securityHeaderOrderList = securityContext.getAsList(SecurityHeaderOrder.class);
        if (securityHeaderOrderList == null) {
            securityContext.putList(SecurityHeaderOrder.class, Collections.<SecurityHeaderOrder>emptyList());
            securityHeaderOrderList = securityContext.getAsList(SecurityHeaderOrder.class);
        }
        if (onTop) {
            securityHeaderOrderList.add(0, new SecurityHeaderOrder(headerElementName, action, encrypted));
        } else {
            securityHeaderOrderList.add(new SecurityHeaderOrder(headerElementName, action, encrypted));
        }
    }

}
