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
package org.apache.wss4j.policy.model;

import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class RequiredParts extends AbstractSecurityAssertion {

    private final List<Header> headers = new ArrayList<Header>();

    public RequiredParts(SPConstants.SPVersion version, List<Header> headers) {
        super(version);
        this.headers.addAll(headers);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getRequiredParts();
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(getName().getPrefix(), getName().getLocalPart(), getName().getNamespaceURI());
        writer.writeNamespace(getName().getPrefix(), getName().getNamespaceURI());
        if (!isNormalized() && isOptional()) {
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_OPTIONAL, "true");
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_IGNORABLE, "true");
        }
        for (int i = 0; i < getHeaders().size(); i++) {
            Header header = getHeaders().get(i);
            final QName headerName = getVersion().getSPConstants().getHeader();
            writer.writeEmptyElement(headerName.getPrefix(), headerName.getLocalPart(), headerName.getNamespaceURI());
            if (header.getName() != null) {
                writer.writeAttribute(SPConstants.NAME, header.getName());
            }
            writer.writeAttribute(SPConstants.NAMESPACE, header.getNamespace());
        }
        writer.writeEndElement();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new RequiredParts(getVersion(), getHeaders());
    }

    public List<Header> getHeaders() {
        return this.headers;
    }

    protected void addHeader(Header header) {
        this.headers.add(header);
    }
}
