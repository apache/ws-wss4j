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

package org.apache.wss4j.dom.processor;

import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;

/**
 * This will process incoming <code>saml2:EncryptedAssertion</code> elements. EncryptedKey
 * children are not supported, only an EncryptedData structure.
 */
public class EncryptedAssertionProcessor implements Processor {
    
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(EncryptedAssertionProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found EncryptedAssertion element");
        }
        
        Element encryptedDataElement =
            XMLUtils.getDirectChildElement(elem, WSConstants.ENC_DATA_LN, WSConstants.ENC_NS);
        if (encryptedDataElement == null) {
            // Maybe it has already been decrypted...
            return Collections.emptyList();
        }
        
        // Type must be "Element" if specified
        String typeStr = encryptedDataElement.getAttributeNS(null, "Type");
        if (typeStr != null && !(WSConstants.ENC_NS + "Element").equals(typeStr)) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY, "badElement", 
                new Object[] {"Element", typeStr}
            );
        }
        
        // Now hand it off to another processor (EncryptedDataProcessor)
        QName el = 
            new QName(encryptedDataElement.getNamespaceURI(), encryptedDataElement.getLocalName());
        Processor proc = request.getWssConfig().getProcessor(el);
        if (proc != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Processing decrypted element with: " + proc.getClass().getName());
            }
            return proc.handleToken(encryptedDataElement, request, wsDocInfo);
        }
        
        return Collections.emptyList();
    }
    
}
