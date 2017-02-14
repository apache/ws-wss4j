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
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.List;

public abstract class AbstractSecuredParts extends RequiredParts {

    private boolean body;
    private Attachments attachments;

    public AbstractSecuredParts(SPConstants.SPVersion version, boolean body, Attachments attachments,
                       List<Header> headers) {
        super(version, headers);

        this.body = body;
        this.attachments = attachments;
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getSignedParts();
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof AbstractSecuredParts)) {
            return false;
        }
        
        AbstractSecuredParts that = (AbstractSecuredParts)object;
        if (body != that.body) {
            return false;
        }
        if (attachments != null && !attachments.equals(that.attachments) 
            || attachments == null && that.attachments != null) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        if (attachments != null) {
            result = 31 * result + attachments.hashCode();
        }
        result = 31 * result + Boolean.valueOf(body).hashCode();
        
        return 31 * result + super.hashCode();
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(getName().getPrefix(), getName().getLocalPart(), getName().getNamespaceURI());
        writer.writeNamespace(getName().getPrefix(), getName().getNamespaceURI());
        if (!isNormalized() && isOptional()) {
            writer.writeAttribute(Constants.ATTR_WSP,
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP),
                                  Constants.ATTR_OPTIONAL, "true");
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP,
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP),
                                  Constants.ATTR_IGNORABLE, "true");
        }
        if (isBody()) {
            final QName body = getVersion().getSPConstants().getBody();
            writer.writeEmptyElement(body.getPrefix(), body.getLocalPart(), body.getNamespaceURI());
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
        if (getAttachments() != null) {
            getAttachments().serialize(writer);
        }
        writer.writeEndElement();
    }

    public boolean isBody() {
        return body;
    }

    protected void setBody(boolean body) {
        this.body = body;
    }

    public Attachments getAttachments() {
        return attachments;
    }

    protected void setAttachments(Attachments attachments) {
        this.attachments = attachments;
    }

}
