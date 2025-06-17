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

/**
 * Class SubjectBean represents a SAML subject (can be used to create
 * both SAML v1.1 and v2.0 statements)
 */
public class SubjectBean {
    private final NameIDBean nameID = new NameIDBean();
    private String subjectConfirmationMethod;
    private KeyInfoBean keyInfo;
    private SubjectConfirmationDataBean subjectConfirmationData;
    private NameIDBean subjectConfirmationNameID;

    /**
     * Constructor SubjectBean creates a new SubjectBean instance.
     */
    public SubjectBean() {
    }

    /**
     * Constructor SubjectBean creates a new SubjectBean instance.
     *
     * @param subjectName of type String
     * @param subjectNameQualifier of type String
     * @param subjectConfirmationMethod of type String
     */
    public SubjectBean(
        String subjectName,
        String subjectNameQualifier,
        String subjectConfirmationMethod
    ) {
        nameID.setNameValue(subjectName);
        nameID.setNameQualifier(subjectNameQualifier);
        this.subjectConfirmationMethod = subjectConfirmationMethod;
    }

    /**
     * Constructor SubjectBean creates a new SubjectBean instance.
     *
     * @param subjectName of type String
     * @param subjectNameQualifier of type String
     * @param subjectConfirmationMethod of type String
     * @param subjectNameIDFormat of type String
     */
    public SubjectBean(
        String subjectName,
        String subjectNameQualifier,
        String subjectConfirmationMethod,
        String subjectNameIDFormat
    ) {
        this(subjectName, subjectNameQualifier, subjectConfirmationMethod);
        nameID.setNameIDFormat(subjectNameIDFormat);
    }

    /**
     * Constructor SubjectBean creates a new SubjectBean instance.
     *
     * @param subjectName of type String
     * @param subjectNameQualifier of type String
     * @param subjectConfirmationMethod of type String
     * @param subjectNameIDFormat of type String
     * @param subjectNameSPProvidedID of type String
     */
    public SubjectBean(
            String subjectName,
            String subjectNameQualifier,
            String subjectConfirmationMethod,
            String subjectNameIDFormat,
            String subjectNameSPProvidedID
    ) {
        this(subjectName, subjectNameQualifier, subjectConfirmationMethod, subjectNameIDFormat);
        nameID.setSPProvidedID(subjectNameSPProvidedID);
    }

    /**
     * Method getSubjectName returns the subjectName of this SubjectBean object.
     *
     * @return the subjectName (type String) of this SubjectBean object.
     */
    public String getSubjectName() {
        return nameID.getNameValue();
    }

    /**
     * Method setSubjectName sets the subjectName of this SubjectBean object.
     *
     * @param subjectName the subjectName of this SubjectBean object.
     */
    public void setSubjectName(String subjectName) {
        nameID.setNameValue(subjectName);
    }

    /**
     * Method getSubjectNameQualifier returns the subjectNameQualifier of this SubjectBean object.
     *
     * @return the subjectNameQualifier (type String) of this SubjectBean object.
     */
    public String getSubjectNameQualifier() {
        return nameID.getNameQualifier();
    }

    /**
     * Method setSubjectNameQualifier sets the subjectNameQualifier of this SubjectBean object.
     *
     * @param subjectNameQualifier the subjectNameQualifier of this SubjectBean object.
     */
    public void setSubjectNameQualifier(String subjectNameQualifier) {
        nameID.setNameQualifier(subjectNameQualifier);
    }

    /**
     * Method getSubjectConfirmationMethod returns the subjectConfirmationMethod of
     * this SubjectBean object.
     *
     * @return the subjectConfirmationMethod (type String) of this SubjectBean object.
     */
    public String getSubjectConfirmationMethod() {
        return subjectConfirmationMethod;
    }

    /**
     * Method setSubjectConfirmationMethod sets the subjectConfirmationMethod of
     * this SubjectBean object.
     *
     * @param subjectConfirmationMethod the subjectConfirmationMethod of this
     *        SubjectBean object.
     */
    public void setSubjectConfirmationMethod(String subjectConfirmationMethod) {
        this.subjectConfirmationMethod = subjectConfirmationMethod;
    }

    /**
     * Method getSubjectNameIDFormat returns the subjectNameIDFormat of this SubjectBean
     * object.
     *
     * @return the subjectNameIDFormat (type String) of this SubjectBean object.
     */
    public String getSubjectNameIDFormat() {
        return nameID.getNameIDFormat();
    }

    /**
     * Method setSubjectNameIDFormat sets the subjectNameIDFormat of this SubjectBean
     * object.
     *
     * @param subjectNameIDFormat the subjectNameIDFormat of this SubjectBean object.
     */
    public void setSubjectNameIDFormat(String subjectNameIDFormat) {
        nameID.setNameIDFormat(subjectNameIDFormat);
    }

    public String getSubjectNameSPNameQualifier() {
        return nameID.getSPNameQualifier();
    }

    public void setSubjectNameSPNameQualifier(String subjectNameSPNameQualifier) {
        nameID.setSPNameQualifier(subjectNameSPNameQualifier);
    }

    public String getSubjectNameSPProvidedID() {
        return nameID.getSPProvidedID();
    }

    public void setSubjectNameSPProvidedID(String subjectNameSPProvidedID) {
        nameID.setSPProvidedID(subjectNameSPProvidedID);
    }

    /**
     * Method getKeyInfo returns the keyInfo of this SubjectBean object.
     *
     * @return the keyInfo (type KeyInfoBean) of this SubjectBean object.
     */
    public KeyInfoBean getKeyInfo() {
        return keyInfo;
    }

    /**
     * Method setKeyInfo sets the keyInfo of this SubjectBean object.
     *
     * @param keyInfo the keyInfo of this SubjectBean object.
     */
    public void setKeyInfo(KeyInfoBean keyInfo) {
        this.keyInfo = keyInfo;
    }

    /**
     * Set the SubjectConfirmationData of this SubjectBean object
     * @return the SubjectConfirmationData of this SubjectBean object
     */
    public SubjectConfirmationDataBean getSubjectConfirmationData() {
        return subjectConfirmationData;
    }

    /**
     * Get the SubjectConfirmationData of this SubjectBean object
     * @param subjectConfirmationData the SubjectConfirmationData of this SubjectBean object
     */
    public void setSubjectConfirmationData(
        SubjectConfirmationDataBean subjectConfirmationData
    ) {
        this.subjectConfirmationData = subjectConfirmationData;
    }

    /**
     * Get the NameId of the SubjectConfirmation object
     * @return the NameId of the SubjectConfirmation object
     */
    public NameIDBean getSubjectConfirmationNameID() {
        return subjectConfirmationNameID;
    }

    /**
     * Set the NameID of the SubjectConfirmation object
     * @param subjectConfirmationNameID the NameID of the SubjectConfirmation object
     */
    public void setSubjectConfirmationNameID(NameIDBean subjectConfirmationNameID) {
        this.subjectConfirmationNameID = subjectConfirmationNameID;
    }

    /**
     * Method equals ...
     *
     * @param o of type Object
     * @return boolean
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SubjectBean)) {
            return false;
        }

        SubjectBean that = (SubjectBean) o;

        if (!nameID.equals(that.nameID)) {
            return false;
        }

        if (subjectConfirmationMethod == null && that.subjectConfirmationMethod != null) {
            return false;
        } else if (subjectConfirmationMethod != null
            && !subjectConfirmationMethod.equals(that.subjectConfirmationMethod)) {
            return false;
        }

        if (keyInfo == null && that.keyInfo != null) {
            return false;
        } else if (keyInfo != null && !keyInfo.equals(that.keyInfo)) {
            return false;
        }

        if (subjectConfirmationData == null && that.subjectConfirmationData != null) {
            return false;
        } else if (subjectConfirmationData != null
            && !subjectConfirmationData.equals(that.subjectConfirmationData)) {
            return false;
        }

        if (subjectConfirmationNameID == null && that.subjectConfirmationNameID != null) {
            return false;
        } else if (subjectConfirmationNameID != null
            && !subjectConfirmationNameID.equals(that.subjectConfirmationNameID)) {
            return false;
        }

        return true;
    }

    /**
     * @return the hashcode of this object
     */
    @Override
    public int hashCode() {
        int result = nameID.hashCode();
        if (subjectConfirmationMethod != null) {
            result = 31 * result + subjectConfirmationMethod.hashCode();
        }
        if (keyInfo != null) {
            result = 31 * result + keyInfo.hashCode();
        }
        if (subjectConfirmationData != null) {
            result = 31 * result + subjectConfirmationData.hashCode();
        }
        if (subjectConfirmationNameID != null) {
            result = 31 * result + subjectConfirmationNameID.hashCode();
        }
        return result;
    }

}
