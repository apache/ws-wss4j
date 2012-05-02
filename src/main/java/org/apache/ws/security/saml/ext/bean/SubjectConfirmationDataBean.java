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

import org.joda.time.DateTime;

/**
 * Class SubjectConfirmationDataBean represents a SAML (2) SubjectConfirmationData. Please note that
 * KeyInfo functionality is in SubjectBean for backwards compatibility reasons.
 */
public class SubjectConfirmationDataBean {
    private String recipient;
    private String address;
    private String inResponseTo;
    private DateTime notBefore;
    private DateTime notAfter;

    /**
     * Constructor SubjectConfirmationDataBean creates a new SubjectConfirmationDataBean instance.
     */
    public SubjectConfirmationDataBean() {
    }

    /**
     * Get the recipient of the SubjectConfirmationDataBean
     * @return the recipient of the SubjectConfirmationDataBean
     */
    public String getRecipient() {
        return recipient;
    }

    /**
     * Set the recipient of the SubjectConfirmationDataBean
     * @param recipient the recipient of the SubjectConfirmationDataBean
     */
    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    /**
     * Get the address of the SubjectConfirmationDataBean
     * @return the address of the SubjectConfirmationDataBean
     */
    public String getAddress() {
        return address;
    }

    /**
     * Set the address of the SubjectConfirmationDataBean
     * @param address the address of the SubjectConfirmationDataBean
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * Get the InResponseTo element of the SubjectConfirmationDataBean
     * @return the InResponseTo element of the SubjectConfirmationDataBean
     */
    public String getInResponseTo() {
        return inResponseTo;
    }

    /**
     * Set the InResponseTo element of the SubjectConfirmationDataBean
     * @param inResponseTo the InResponseTo element of the SubjectConfirmationDataBean
     */
    public void setInResponseTo(String inResponseTo) {
        this.inResponseTo = inResponseTo;
    }

    /**
     * Get the NotBefore time of the SubjectConfirmationDataBean
     * @return the NotBefore time of the SubjectConfirmationDataBean
     */
    public DateTime getNotBefore() {
        return notBefore;
    }

    /**
     * Set the NotBefore time of the SubjectConfirmationDataBean
     * @param notBefore the NotBefore time of the SubjectConfirmationDataBean
     */
    public void setNotBefore(DateTime notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * Get the NotOnOrAfter time of the SubjectConfirmationDataBean
     * @return the NotOnOrAfter time of the SubjectConfirmationDataBean
     */
    public DateTime getNotAfter() {
        return notAfter;
    }

    /**
     * Set the NotOnOrAfter time of the SubjectConfirmationDataBean
     * @param notAfter the NotOnOrAfter time of the SubjectConfirmationDataBean
     */
    public void setNotAfter(DateTime notAfter) {
        this.notAfter = notAfter;
    }
    
    /**
     * Method equals ...
     *
     * @param o of type Object
     * @return boolean
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SubjectConfirmationDataBean)) return false;

        SubjectConfirmationDataBean that = (SubjectConfirmationDataBean) o;

        if (recipient == null && that.recipient != null) {
            return false;
        } else if (recipient != null && !recipient.equals(that.recipient)) {
            return false;
        }
        
        if (address == null && that.address != null) {
            return false;
        } else if (address != null && !address.equals(that.address)) {
            return false;
        }
        
        if (inResponseTo == null && that.inResponseTo != null) {
            return false;
        } else if (inResponseTo != null && !inResponseTo.equals(that.inResponseTo)) {
            return false;
        }
        
        if (notBefore == null && that.notBefore != null) {
            return false;
        } else if (notBefore != null && !notBefore.equals(that.notBefore)) {
            return false;
        }
        
        if (notAfter == null && that.notAfter != null) {
            return false;
        } else if (notAfter != null && !notAfter.equals(that.notAfter)) {
            return false;
        }

        return true;
    }

    /**
     * @return the hashcode of this object
     */
    @Override
    public int hashCode() {
        int result = 0;
        if (recipient != null) {
            result = recipient.hashCode();
        }
        if (address != null) {
            result = 31 * result + address.hashCode();
        }
        if (inResponseTo != null) {
            result = 31 * result + inResponseTo.hashCode();
        }
        if (notBefore != null) {
            result = 31 * result + notBefore.hashCode();
        }
        if (notAfter != null) {
            result = 31 * result + notAfter.hashCode();
        }
        return result;
    }

}
