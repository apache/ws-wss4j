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
package org.swssf.wss.impl;

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.xmlsec.impl.DocumentContextImpl;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

/**
 * A concrete WSSDocumentContext Implementation
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSDocumentContextImpl extends DocumentContextImpl implements WSSDocumentContext {

    public String getSOAPMessageVersionNamespace() {
        if (getPath().size() >= 1 && getPath().get(0).equals(WSSConstants.TAG_soap11_Envelope)) {
            return WSSConstants.NS_SOAP11;
        } else if (getPath().size() >= 1 && getPath().get(0).equals(WSSConstants.TAG_soap12_Envelope)) {
            return WSSConstants.NS_SOAP12;
        }
        return null;
    }

    public boolean isInSOAPHeader() {
        return (getPath().size() > 1
                && getPath().get(1).getLocalPart().equals(WSSConstants.TAG_soap_Header_LocalName)
                && getPath().get(0).getNamespaceURI().equals(getPath().get(1).getNamespaceURI()));
    }

    public boolean isInSOAPBody() {
        return (getPath().size() > 1
                && getPath().get(1).getLocalPart().equals(WSSConstants.TAG_soap_Body_LocalName)
                && getPath().get(0).getNamespaceURI().equals(getPath().get(1).getNamespaceURI()));
    }

    private boolean inSecurityHeader = false;

    public boolean isInSecurityHeader() {
        return inSecurityHeader;
    }

    public void setInSecurityHeader(boolean inSecurityHeader) {
        this.inSecurityHeader = inSecurityHeader;
    }

    @Override
    protected WSSDocumentContextImpl clone() throws CloneNotSupportedException {
        WSSDocumentContextImpl documentContext = new WSSDocumentContextImpl();
        documentContext.setEncoding(this.getEncoding());
        List<QName> subPath = new ArrayList<QName>(this.getPath());
        documentContext.setPath(subPath);
        documentContext.setInSecurityHeader(isInSecurityHeader());
        documentContext.setContentTypeMap(getContentTypeMap());
        return documentContext;
    }
}
