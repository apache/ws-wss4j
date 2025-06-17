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

package org.apache.wss4j.common.saml.bean;

import java.util.List;
import java.util.ArrayList;

/**
 * Class SamlAttribute represents an instance of a SAML attribute.
 */
public class AttributeBean {
    private String simpleName;
    private String qualifiedName;
    private String nameFormat;
    private List<Object> attributeValues;

    /**
     * Constructor SamlAttribute creates a new SamlAttribute instance.
     */
    public AttributeBean() {
        attributeValues = new ArrayList<>();
    }

    /**
     * Constructor SamlAttribute creates a new SamlAttribute instance.
     *
     * @param simpleName of type String
     * @param qualifiedName of type String
     * @param attributeValues of type List<Object>
     */
    public AttributeBean(String simpleName, String qualifiedName, List<Object> attributeValues) {
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
     * @return the nameFormat of this SamlAttribute object
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
    public List<Object> getAttributeValues() {
        return attributeValues;
    }

    /**
     * Method setAttributeValues sets the attributeValues of this SamlAttribute object.
     *
     * @param attributeValues the attributeValues of this SamlAttribute object.
     */
    public void setAttributeValues(List<Object> attributeValues) {
        this.attributeValues = attributeValues;
    }

    public void addAttributeValue(Object attributeValue) {
        if (attributeValues == null) {
            attributeValues = new ArrayList<>();
        }
        attributeValues.add(attributeValue);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AttributeBean)) {
            return false;
        }

        AttributeBean that = (AttributeBean) o;

        if (attributeValues == null && that.attributeValues != null) {
            return false;
        } else if (attributeValues != null && !attributeValues.equals(that.attributeValues)) {
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
        return result;
    }
}
