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

package org.apache.wss4j.dom.action;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;

public abstract class AbstractDerivedAction {
    
    protected Node findPlaceToInsertDKT(RequestData reqData) {
        Element secHeader = reqData.getSecHeader().getSecurityHeader();
        Node firstChild = secHeader.getFirstChild();
        while (firstChild != null) {
            if (firstChild instanceof Element && 
                WSConstants.ENC_NS.equals(((Element)firstChild).getNamespaceURI())
                && "EncryptedKey".equals(((Element)firstChild).getLocalName())
                && firstChild.getNextSibling() != null) {
                return firstChild.getNextSibling();
            }
            firstChild = firstChild.getNextSibling();
        }
        return null;
    }

}
