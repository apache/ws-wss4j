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
package org.swssf.xmlsec.ext;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * This class holds per document, context informations
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface DocumentContext {

    /**
     * @return The Encoding of the Document
     */
    public String getEncoding();

    /**
     * Adds a Element to the path
     *
     * @param qName The QName of the path element
     */
    public void addPathElement(QName qName);

    /**
     * Removes a element from the path
     *
     * @return the removed element
     */
    public QName removePathElement();

    /**
     * @return The actual path in the xml
     */
    public List<QName> getPath();

    /**
     * Returns the parent element of the actual eventtype
     *
     * @param eventType current event type
     * @return the name of the parent element
     */
    public QName getParentElement(int eventType);

    /**
     * @return The current level in the document
     */
    public int getDocumentLevel();

    /**
     * Indicates if we currently stay in an encrypted content
     */
    public void setIsInEncryptedContent();

    /**
     * unset when we leave the encrypted content
     */
    public void unsetIsInEncryptedContent();

    /**
     * @return true if we currently stay in encrypted content
     */
    public boolean isInEncryptedContent();

    /**
     * Indicates if we currently stay in a signed content
     */
    public void setIsInSignedContent();

    /**
     * unset when we leave the signed content
     */
    public void unsetIsInSignedContent();

    /**
     * @return true if we currently stay in signed content
     */
    public boolean isInSignedContent();
}
