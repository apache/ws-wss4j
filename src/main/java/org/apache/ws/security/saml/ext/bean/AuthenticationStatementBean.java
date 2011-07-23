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
 * Class AuthenticationStatementBean represents the raw data required to create
 * a SAML v1.1 or v2.0 authentication statement.
 *
 * Created on May 20, 2009
 */
public class AuthenticationStatementBean {
    private SubjectBean subject;
    DateTime authenticationInstant;
    private String authenticationMethod;
    private SubjectLocalityBean subjectLocality;
    private String sessionIndex;

    /**
     * Default constructor
     */
    public AuthenticationStatementBean() {
    }

    /**
     * Construct a new AuthenticationStatementBean
     * 
     * @param subject the Subject to set 
     * @param authenticationMethod the Authentication Method to set
     * @param authenticationInstant the Authentication Instant to set
     */
    public AuthenticationStatementBean(
        SubjectBean subject, 
        String authenticationMethod,
        DateTime authenticationInstant
    ) {
        this.subject = subject;
        this.authenticationMethod = authenticationMethod;
        this.authenticationInstant = authenticationInstant;
    }

    /**
     * Get the Subject
     * @return the subject
     */
    public SubjectBean getSubject() {
        return subject;
    }

    /**
     * Set the subject
     * @param subject the SubjectBean instance to set
     */
    public void setSubject(SubjectBean subject) {
        this.subject = subject;
    }

    /**
     * Get the authentication method
     * @return the authentication method
     */
    public String getAuthenticationMethod() {
        return authenticationMethod;
    }

    /**
     * Set the authentication method
     * @param authenticationMethod the authentication method
     */
    public void setAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    /**
     * Get the authentication instant
     * @return the authentication instant
     */
    public DateTime getAuthenticationInstant() {
        return authenticationInstant;
    }

    /**
     * Set the authentication instant
     * @param authenticationInstant the authentication instant
     */
    public void setAuthenticationInstant(DateTime authenticationInstant) {
        this.authenticationInstant = authenticationInstant;
    }
    
    /**
     * Get Subject Locality.
     * 
     * @return the subjectLocality
     */
    public final SubjectLocalityBean getSubjectLocality() {
        return subjectLocality;
    }

    /**
     * Set Subject Locality.
     * 
     * @param subjectLocality the subjectLocality to set
     */
    public final void setSubjectLocality(final SubjectLocalityBean subjectLocality) {
        this.subjectLocality = subjectLocality;
    }
    
    /**
     * Get the session index.
     * 
     * @return the sessionIndex
     */
    public final String getSessionIndex() {
        return sessionIndex;
    }

    /**
     * Set the session index.
     * 
     * @param sessionIndex the sessionIndex to set
     */
    public final void setSessionIndex(final String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthenticationStatementBean)) return false;

        AuthenticationStatementBean that = (AuthenticationStatementBean) o;

        if (authenticationInstant == null && that.authenticationInstant != null) {
            return false;
        } else if (authenticationInstant != null 
            && !authenticationInstant.equals(that.authenticationInstant)) {
            return false;
        }
        
        if (authenticationMethod == null && that.authenticationMethod != null) {
            return false;
        } else if (authenticationMethod != null 
            && !authenticationMethod.equals(that.authenticationMethod)) {
            return false;
        }
        
        if (subject == null && that.subject != null) {
            return false;
        } else if (subject != null 
            && !subject.equals(that.subject)) {
            return false;
        }
        
        if (subjectLocality == null && that.subjectLocality != null) {
            return false;
        } else if (subjectLocality != null && !subjectLocality.equals(that.subjectLocality)) {
            return false;
        }

        if (sessionIndex == null && that.sessionIndex != null) {
            return false;
        } else if (sessionIndex != null && !sessionIndex.equals(that.sessionIndex)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = subject != null ? subject.hashCode() : 0;
        result = 31 * result + (authenticationInstant != null ? authenticationInstant.hashCode() : 0);
        result = 31 * result + (authenticationMethod != null ? authenticationMethod.hashCode() : 0);
        result = 31 * result + (subjectLocality != null ? subjectLocality.hashCode() : 0);
        result = 31 * result + (sessionIndex != null ? sessionIndex.hashCode() : 0);
        return result;
    }
}
