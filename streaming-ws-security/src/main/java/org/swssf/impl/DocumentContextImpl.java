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
package org.swssf.impl;

import org.swssf.ext.Constants;
import org.swssf.ext.DocumentContext;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import java.util.ArrayList;
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

    public String getSOAPMessageVersionNamespace() {
        if (path.size() >= 1 && path.get(0).equals(Constants.TAG_soap11_Envelope)) {
            return Constants.NS_SOAP11;
        } else if (path.size() >= 1 && path.get(0).equals(Constants.TAG_soap12_Envelope)) {
            return Constants.NS_SOAP12;
        }
        return null;
    }

    public void addPathElement(QName qName) {
        path.add(qName);
    }

    public QName removePathElement() {
        return path.remove(path.size() - 1);
    }

    protected void setPath(List<QName> path) {
        this.path = path;
    }

    public List<QName> getPath() {
        return path;
    }

    public QName getParentElement(int eventType) {
        if (eventType == XMLStreamConstants.START_ELEMENT || eventType == XMLStreamConstants.END_ELEMENT) {
            if (path.size() >= 2) {
                return path.get(path.size() - 2);
            } else {
                return nullElement;
            }
        } else {
            if (path.size() >= 1) {
                return path.get(path.size() - 1);
            } else {
                return nullElement;
            }
        }
    }

    public boolean isInSOAPHeader() {
        return (path.size() > 1
                && path.get(1).getLocalPart().equals(Constants.TAG_soap_Header_LocalName)
                && path.get(0).getNamespaceURI().equals(path.get(1).getNamespaceURI()));
    }

    public boolean isInSOAPBody() {
        return (path.size() > 1
                && path.get(1).getLocalPart().equals(Constants.TAG_soap_Body_LocalName)
                && path.get(0).getNamespaceURI().equals(path.get(1).getNamespaceURI()));
    }

    public int getDocumentLevel() {
        return path.size();
    }

    private boolean inSecurityHeader = false;

    public boolean isInSecurityHeader() {
        return inSecurityHeader;
    }

    public void setInSecurityHeader(boolean inSecurityHeader) {
        this.inSecurityHeader = inSecurityHeader;
    }

    private int actualEncryptedContentCounter = 0;

    public synchronized void setIsInEncryptedContent() {
        this.actualEncryptedContentCounter++;
    }

    public synchronized void unsetIsInEncryptedContent() {
        this.actualEncryptedContentCounter--;
    }

    public boolean isInEncryptedContent() {
        return this.actualEncryptedContentCounter > 0;
    }

    private int actualSignedContentCounter = 0;

    public synchronized void setIsInSignedContent() {
        this.actualSignedContentCounter++;
    }

    public synchronized void unsetIsInSignedContent() {
        this.actualSignedContentCounter--;
    }

    public boolean isInSignedContent() {
        return this.actualSignedContentCounter > 0;
    }

    @Override
    protected DocumentContextImpl clone() throws CloneNotSupportedException {
        super.clone();
        DocumentContextImpl documentContext = new DocumentContextImpl();
        List<QName> subPath = new ArrayList<QName>();
        subPath.addAll(this.path);
        documentContext.setEncoding(this.encoding);
        documentContext.setPath(subPath);
        documentContext.setInSecurityHeader(isInSecurityHeader());
        documentContext.actualEncryptedContentCounter = this.actualEncryptedContentCounter;
        documentContext.actualSignedContentCounter = this.actualSignedContentCounter;
        return documentContext;
    }
}
