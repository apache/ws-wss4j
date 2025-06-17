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
 * Class SamlAttributeStatement represents a SAML attribute statement
 */
public class AttributeStatementBean {
    private SubjectBean subject;
    private List<AttributeBean> attributeBeans;

    /**
     * Constructor SamlAttributeStatement creates a new SamlAttributeStatement instance.
     */
    public AttributeStatementBean() {
        attributeBeans = new ArrayList<>();
    }

    /**
     * Constructor SamlAttributeStatement creates a new SamlAttributeStatement instance.
     * @param subject A new SubjectBean instance
     * @param attributeBeans A list of Attributes
     */
    public AttributeStatementBean(
        SubjectBean subject,
        List<AttributeBean> attributeBeans
    ) {
        this.subject = subject;
        this.attributeBeans = attributeBeans;
    }

    /**
     * Method getSamlAttributes returns the samlAttributes of this SamlAttributeStatement object.
     *
     * @return the samlAttributes (type List<SamlAttribute>) of this SamlAttributeStatement object.
     */
    public List<AttributeBean> getSamlAttributes() {
        return attributeBeans;
    }

    /**
     * Method setSamlAttributes sets the samlAttributes of this SamlAttributeStatement object.
     *
     * @param attributeBeans the samlAttributes of this SamlAttributeStatement object.
     *
     */
    public void setSamlAttributes(List<AttributeBean> attributeBeans) {
        this.attributeBeans = attributeBeans;
    }

    /**
     * Get the Subject
     * @return the Subject
     */
    public SubjectBean getSubject() {
        return subject;
    }

    /**
     * Set the Subject
     * @param subject the SubjectBean instance to set
     */
    public void setSubject(SubjectBean subject) {
        this.subject = subject;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AttributeStatementBean)) {
            return false;
        }

        AttributeStatementBean that = (AttributeStatementBean) o;

        if (attributeBeans == null && that.attributeBeans != null) {
            return false;
        } else if (attributeBeans != null && !attributeBeans.equals(that.attributeBeans)) {
            return false;
        }

        if (subject == null && that.subject != null) {
            return false;
        } else if (subject != null && !subject.equals(that.subject)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = subject != null ? subject.hashCode() : 0;
        result = 31 * result + (attributeBeans != null ? attributeBeans.hashCode() : 0);
        return result;
    }
}
