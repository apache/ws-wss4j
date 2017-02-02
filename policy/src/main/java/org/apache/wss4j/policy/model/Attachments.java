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

public class Attachments extends AbstractSecurityAssertion {

    private boolean contentSignatureTransform;
    private boolean attachmentCompleteSignatureTransform;

    public Attachments(SPConstants.SPVersion version, boolean contentSignatureTransform, 
                       boolean attachmentCompleteSignatureTransform) {
        super(version);

        this.contentSignatureTransform = contentSignatureTransform;
        this.attachmentCompleteSignatureTransform = attachmentCompleteSignatureTransform;
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getAttachments();
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        
        if (!(object instanceof Attachments)) {
            return false;
        }
        
        Attachments that = (Attachments)object;
        if (contentSignatureTransform != that.contentSignatureTransform) {
            return false;
        }
        if (attachmentCompleteSignatureTransform != that.attachmentCompleteSignatureTransform) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + Boolean.hashCode(contentSignatureTransform);
        result = 31 * result + Boolean.hashCode(attachmentCompleteSignatureTransform);
        
        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new Attachments(getVersion(), isContentSignatureTransform(), isAttachmentCompleteSignatureTransform());
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
        if (isContentSignatureTransform()) {
            writer.writeEmptyElement(
                    getVersion().getSPConstants().getContentSignatureTransform().getPrefix(),
                    getVersion().getSPConstants().getContentSignatureTransform().getLocalPart(),
                    getVersion().getSPConstants().getContentSignatureTransform().getNamespaceURI());
            writer.writeNamespace(
                    getVersion().getSPConstants().getContentSignatureTransform().getPrefix(),
                    getVersion().getSPConstants().getContentSignatureTransform().getNamespaceURI());
        }
        if (isAttachmentCompleteSignatureTransform()) {
            writer.writeEmptyElement(
                    getVersion().getSPConstants().getAttachmentCompleteSignatureTransform().getPrefix(),
                    getVersion().getSPConstants().getAttachmentCompleteSignatureTransform().getLocalPart(),
                    getVersion().getSPConstants().getAttachmentCompleteSignatureTransform().getNamespaceURI());
            writer.writeNamespace(
                    getVersion().getSPConstants().getAttachmentCompleteSignatureTransform().getPrefix(),
                    getVersion().getSPConstants().getAttachmentCompleteSignatureTransform().getNamespaceURI());
        }
        writer.writeEndElement();
    }

    public boolean isContentSignatureTransform() {
        return contentSignatureTransform;
    }

    protected void setContentSignatureTransform(boolean contentSignatureTransform) {
        this.contentSignatureTransform = contentSignatureTransform;
    }

    public boolean isAttachmentCompleteSignatureTransform() {
        return attachmentCompleteSignatureTransform;
    }

    protected void setAttachmentCompleteSignatureTransform(boolean attachmentCompleteSignatureTransform) {
        this.attachmentCompleteSignatureTransform = attachmentCompleteSignatureTransform;
    }
}
