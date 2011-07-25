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

package org.apache.ws.security.saml.ext.bean;

import java.util.List;
import java.util.ArrayList;

/**
 * Class SamlAttribute represents an instance of a SAML attribute.
 * <p/>
 * Created on May 18, 2009
 */
public class AttributeBean {
    private String simpleName;
    private String qualifiedName;
    private String nameFormat;
    private List<String> attributeValues;
    private List<?> customAttributeValues;

    /**
     * Constructor SamlAttribute creates a new SamlAttribute instance.
     */
    public AttributeBean() {
        attributeValues = new ArrayList<String>();
    }

    /**
     * Constructor SamlAttribute creates a new SamlAttribute instance.
     * 
     * @param simpleName of type String
     * @param qualifiedName of type String
     * @param attributeValues of type List<String>
     */
    public AttributeBean(String simpleName, String qualifiedName, List<String> attributeValues) {
        this.simpleName = simpleName;
        this.qualifiedName = qualifiedName;
        this.attributeValues = attributeValues;
    }

    /**
     * Method getSimpleName returns the simpleName of this SamlAttribute object.
     *
     * @return the simpleName (type String) of this SamlAttribute object.
     */
    public String getSimpleName() {
        return simpleName;
    }

    /**
     * Method setSimpleName sets the simpleName of this SamlAttribute object.
     *
     * @param simpleName the simpleName of this SamlAttribute object.
     */
    public void setSimpleName(String simpleName) {
        this.simpleName = simpleName;
    }
    
    /**
     * Method getNameFormat returns the nameFormat of this SamlAttribute object
     * 
     * @return he nameFormat of this SamlAttribute object
     */
    public String getNameFormat() {
        return nameFormat;
    }
    
    /**
     * Method setNameFormat sets the nameFormat of this SamlAttribute object.
     *
     * @param nameFormat the nameFormat of this SamlAttribute object.
     */
    public void setNameFormat(String nameFormat) {
        this.nameFormat = nameFormat;
    }

    /**
     * Method getQualifiedName returns the qualifiedName of this SamlAttribute object.
     *
     * @return the qualifiedName (type String) of this SamlAttribute object.
     */
    public String getQualifiedName() {
        return qualifiedName;
    }

    /**
     * Method setQualifiedName sets the qualifiedName of this SamlAttribute object.
     *
     * @param qualifiedName the qualifiedName of this SamlAttribute object.
     */
    public void setQualifiedName(String qualifiedName) {
        this.qualifiedName = qualifiedName;
    }

    /**
     * Method getAttributeValues returns the attributeValues of this SamlAttribute object.
     *
     * @return the attributeValues (type List) of this SamlAttribute object.
     */
    public List<String> getAttributeValues() {
        return attributeValues;
    }

    /**
     * Method setAttributeValues sets the attributeValues of this SamlAttribute object.
     *
     * @param attributeValues the attributeValues of this SamlAttribute object.
     */
    public void setAttributeValues(List<String> attributeValues) {
        this.attributeValues = attributeValues;
    }
    
    /**
     * Method setCustomAttributeValues sets the attributeValues of this SamlAttribute object.
     * This method allows the user to specify OpenSAML XMLObject attributes.
     *
     * @param customAttributeValues the attributeValues of this SamlAttribute object.
     */
    public void setCustomAttributeValues(List<?> customAttributeValues) {
        this.customAttributeValues = customAttributeValues;
    }
    
    /**
     * Method getCustomAttributeValues returns the attributeValues of this SamlAttribute object.
     *
     * @return the attributeValues (type List) of this SamlAttribute object.
     */
    public List<?> getCustomAttributeValues() {
        return customAttributeValues;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AttributeBean)) return false;

        AttributeBean that = (AttributeBean) o;

        if (attributeValues == null && that.attributeValues != null) {
            return false;
        } else if (attributeValues != null && !attributeValues.equals(that.attributeValues)) {
            return false;
        }
        
        if (customAttributeValues == null && that.customAttributeValues != null) {
            return false;
        } else if (customAttributeValues != null 
                && !customAttributeValues.equals(that.customAttributeValues)) {
            return false;
        }
        
        if (qualifiedName == null && that.qualifiedName != null) {
            return false;
        } else if (qualifiedName != null && !qualifiedName.equals(that.qualifiedName)) {
            return false;
        }
        
        if (nameFormat == null && that.nameFormat != null) {
            return false;
        } else if (nameFormat != null && !nameFormat.equals(that.nameFormat)) {
            return false;
        }
        
        if (simpleName == null && that.simpleName != null) {
            return false;
        } else if (simpleName != null && !simpleName.equals(that.simpleName)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = 0;
        if (simpleName != null) {
            result = 31 * result + simpleName.hashCode();
        }
        if (qualifiedName != null) {
            result = 31 * result + qualifiedName.hashCode();
        }
        if (nameFormat != null) {
            result = 31 * result + nameFormat.hashCode();
        }
        if (attributeValues != null) {
            result = 31 * result + attributeValues.hashCode();
        }
        if (customAttributeValues != null) {
            result = 31 * result + customAttributeValues.hashCode();
        }
        return result;
    }
}
