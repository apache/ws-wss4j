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

package org.apache.ws.security;

import org.w3c.dom.Element;

/**
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class WSEncryptionPart {

    private String name;
    private String namespace;
    private String encModifier;
    private String encId;
    private String id;
    private Element element;
    
    /**
     * An xpath expression pointing to the data element
     * that may be specified in case the encryption part is of type
     * <code>org.apache.ws.security.WSConstants.PART_TYPE_ELEMENT</code>
     */
    private String xpath;
    
    /**
     * Constructor to initialize part structure with element, namespace, and modifier.
     * 
     * This constructor initializes the parts structure to lookup for a
     * fully qualified name of an element to encrypt or sign. The modifier
     * controls how encryption encrypts the element, signature processing does
     * not use the modifier information.
     * 
     * <p/>
     * 
     * Regarding the modifier ("Content" or "Element") refer to the W3C
     * XML Encryption specification. 
     * 
     * @param nm Element's name
     * @param nmspace Element's namespace
     * @param encMod The encryption modifier
     */
    public WSEncryptionPart(String nm, String nmspace, String encMod) {
        name = nm;
        namespace = nmspace;
        encModifier = encMod;
        id = null;
    }
    
    /**
     * Constructor to initialize part structure with element id.
     * 
     * This constructor initializes the parts structure to lookup for a
     * an element with the given Id to encrypt or sign. 
     * 
     * @param id The Id to of the element to process
     */
    public WSEncryptionPart(String id) {
        this.id = id;
        name = namespace = encModifier = null;
    }
    
    /**
     * Constructor to initialize part structure with element id and modifier.
     * 
     * This constructor initializes the parts structure to lookup for a
     * an element with the given Id to encrypt or sign. The modifier
     * controls how encryption encrypts the element, signature processing does
     * not use the modifier information.
     * 
     * <p/>
     * 
     * Regarding the modifier ("Content" or "Element") refer to the W3C
     * XML Encryption specification. 
     * 
     * @param id The Id to of the element to process
     * @param encMod The encryption modifier
     */
    public WSEncryptionPart(String id, String encMod) {
        this.id = id;
        encModifier = encMod;
        name = namespace = null;
    }
    
    /**
     * @return the local name of the element to encrypt.
     */
    public String getName() {
        return name;
    }

    /**
     * @return the namespace of the element to encrypt
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * @return the encryption modifier
     */
    public String getEncModifier() {
        return encModifier;
    }
    
    /**
     * Set the encryption modifier
     */
    public void setEncModifier(String encModifier) {
        this.encModifier = encModifier;
    }

    /**
     * @return Returns the id.
     */
    public String getId() {
        return id;
    }
    
    /**
     * Set the id
     * @param id
     */
    public void setId(String id) {
        this.id = id;
    }
    
    public void setEncId(String id) {
        encId = id;
    }
    
    public String getEncId() {
        return encId;
    }

    /**
     * @return the xpath
     */
    public String getXpath() {
        return xpath;
    }

    /**
     * @param xpath the xpath to set
     */
    public void setXpath(String xpath) {
        this.xpath = xpath;
    }
    
    /**
     * Set the DOM Element corresponding to this EncryptionPart
     * @param element the DOM Element corresponding to this EncryptionPart
     */
    public void setElement(Element element) {
        this.element = element;
    }
    
    /**
     * Get the DOM Element corresponding to this EncryptionPart
     * @return the DOM Element corresponding to this EncryptionPart
     */
    public Element getElement() {
        return element;
    }
    
}
