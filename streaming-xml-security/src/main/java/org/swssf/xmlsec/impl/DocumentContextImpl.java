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
package org.swssf.xmlsec.impl;

import org.swssf.xmlsec.ext.DocumentContext;
import org.swssf.xmlsec.ext.XMLSecurityConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;

/**
 * A concrete DocumentContext Implementation
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DocumentContextImpl implements DocumentContext, Cloneable {

    private static final QName nullElement = new QName("", "");
    private List<QName> path = new ArrayList<QName>(10);
    private String encoding;

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public void addPathElement(QName qName) {
        getPath().add(qName);
    }

    public QName removePathElement() {
        return getPath().remove(getPath().size() - 1);
    }

    protected void setPath(List<QName> path) {
        this.path = path;
    }

    public List<QName> getPath() {
        return path;
    }

    public QName getParentElement(int eventType) {
        if (eventType == XMLStreamConstants.START_ELEMENT || eventType == XMLStreamConstants.END_ELEMENT) {
            if (getPath().size() >= 2) {
                return getPath().get(getPath().size() - 2);
            } else {
                return nullElement;
            }
        } else {
            if (getPath().size() >= 1) {
                return getPath().get(getPath().size() - 1);
            } else {
                return nullElement;
            }
        }
    }

    public int getDocumentLevel() {
        return getPath().size();
    }

    Deque<XMLSecurityConstants.ContentType> contentTypeDeque = new LinkedList<XMLSecurityConstants.ContentType>();

    public synchronized void setIsInEncryptedContent() {
        contentTypeDeque.push(XMLSecurityConstants.ContentType.ENCRYPTION);
    }

    public synchronized void unsetIsInEncryptedContent() {
        if (!contentTypeDeque.isEmpty()) {
            contentTypeDeque.pop();
        }
    }

    public boolean isInEncryptedContent() {
        return contentTypeDeque.contains(XMLSecurityConstants.ContentType.ENCRYPTION);
    }

    public synchronized void setIsInSignedContent() {
        contentTypeDeque.push(XMLSecurityConstants.ContentType.SIGNATURE);
    }

    public synchronized void unsetIsInSignedContent() {
        if (!contentTypeDeque.isEmpty()) {
            contentTypeDeque.pop();
        }
    }

    public boolean isInSignedContent() {
        return contentTypeDeque.contains(XMLSecurityConstants.ContentType.SIGNATURE);
    }

    public Deque<XMLSecurityConstants.ContentType> getContentTypeDeque() {
        return contentTypeDeque;
    }

    protected void setContentTypeDeque(Deque<XMLSecurityConstants.ContentType> contentTypeDeque) {
        this.contentTypeDeque.addAll(contentTypeDeque);
    }

    @Override
    protected DocumentContextImpl clone() throws CloneNotSupportedException {
        super.clone();
        DocumentContextImpl documentContext = new DocumentContextImpl();
        List<QName> subPath = new ArrayList<QName>();
        subPath.addAll(this.getPath());
        documentContext.setEncoding(this.encoding);
        documentContext.setPath(subPath);
        documentContext.setContentTypeDeque(getContentTypeDeque());
        return documentContext;
    }
}
