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
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;

/**
 * This will process incoming <code>saml2:EncryptedAssertion</code> elements.
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

        List<WSSecurityEngineResult> completeResults = new LinkedList<>();

        // Check all EncryptedKey elements
        for (Node currentChild = elem.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                    && "EncryptedKey".equals(currentChild.getLocalName())
                    && WSConstants.ENC_NS.equals(currentChild.getNamespaceURI())) {
                QName el =
                    new QName(((Element)currentChild).getNamespaceURI(),
                              ((Element)currentChild).getLocalName());
                Processor proc = request.getWssConfig().getProcessor(el);
                if (proc != null) {
                    completeResults.addAll(proc.handleToken(((Element)currentChild), request, wsDocInfo));
                }
            }
        }

        // If we have processed EncryptedKey elements, then the Assertion is already decrypted
        // at this point. Process it accordingly.
        if (!completeResults.isEmpty()) {
            for (WSSecurityEngineResult r : completeResults) {
                List<WSDataRef> dataRefs =
                    (List<WSDataRef>)r.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (dataRefs != null) {
                    for (WSDataRef dataRef : dataRefs) {
                        if (WSConstants.SAML_TOKEN.equals(dataRef.getName())
                            || WSConstants.SAML2_TOKEN.equals(dataRef.getName())) {
                            // Get hold of the plain text element
                            Element decryptedElem = dataRef.getProtectedElement();
                            QName el = new QName(decryptedElem.getNamespaceURI(), decryptedElem.getLocalName());
                            Processor proc = request.getWssConfig().getProcessor(el);
                            if (proc != null) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Processing decrypted element with: " + proc.getClass().getName());
                                }
                                List<WSSecurityEngineResult> results =
                                    proc.handleToken(decryptedElem, request, wsDocInfo);
                                completeResults.addAll(0, results);
                                return completeResults;
                            }
                        }
                    }
                }
            }
        }

        // Otherwise decrypt the element ourselves

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
