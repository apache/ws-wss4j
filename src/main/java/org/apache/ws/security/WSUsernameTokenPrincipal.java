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

import java.security.Principal;

/**
 * This class implements the <code>Principal</code> interface and
 * represents a UsernameToken user. 
 * <p/>In addition to the principal's name
 * this principal object also contains the nonce and created time of the
 * UsernameToken (refer to the OASIS WS Security specification, UsernameToken
 * profile). These values are set only if the password of UsernameToken was of
 * type <code>PasswordDigest</code>.
 * <p/>Furthermore the password type is
 * provided to the application. The password type is the string of the type
 * attribute of the password element inside the username token. Refer to the
 * OASIS WSS specification for predefined password types. <p/>The
 * <code>equals()</code> method use the prinicipal's name only and does not
 * compare nonce or created time. 
 * <p/>Modelled according to the example provided
 * by JAAS documentation 
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@siemens.com).
 * @see java.security.Principal
 * @see javax.security.auth.Subject
 */
public class WSUsernameTokenPrincipal implements Principal, java.io.Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 5608648208455259722L;
    private String name;
    private String nonce;
    private String password;
    private String createdTime;
    private String passwordType;
    private boolean digest = false;

    /**
     * Create a WSUsernameTokenPrincipal with a WSUsernameToken username.
     *
     * @param name the WSUsernameToken username for this user.
     */
    public WSUsernameTokenPrincipal(String name, boolean digest) {
        this.name = name;
        this.digest = digest;
    }

    /**
     * Return the WSUsernameToken username for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return the WSUsernameToken username for this <code>WSUsernameTokenPrincipal</code>
     */
    public String getName() {
        return name;
    }

    /**
     * Return the WSUsernameToken password type for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return true if the password type was <code>PassowrdDigest</code>
     */
    public boolean isPasswordDigest() {
        return digest;
    }

    /**
     * Set the WSUsernameToken password for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Return the WSUsernameToken password for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return the WSUsernameToken password for this <code>WSUsernameTokenPrincipal</code>
     */
    public String getPassword() {
        return password;
    }

    /**
     * Set the WSUsernameToken nonce for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @param nonce
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Return the WSUsernameToken nonce for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return the WSUsernameToken nonce for this <code>WSUsernameTokenPrincipal</code>
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Set the WSUsernameToken created time for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @param createdTime
     */
    public void setCreatedTime(String createdTime) {
        this.createdTime = createdTime;
    }

    /**
     * Return the WSUsernameToken created time for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return the WSUsernameToken created time for this <code>WSUsernameTokenPrincipal</code>
     */
    public String getCreatedTime() {
        return createdTime;
    }

    /**
     * Return a string representation of this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return a string representation of this <code>WSUsernameTokenPrincipal</code>.
     */
    public String toString() {
        return ("WSUsernameTokenPrincipal:  " + name);
    }

    /**
     * @return Returns the passwordType.
     */
    public String getPasswordType() {
        return passwordType;
    }
    
    /**
     * @param passwordType The passwordType to set.
     */
    public void setPasswordType(String passwordType) {
        this.passwordType = passwordType;
    }
    
    /**
     * Compares the specified Object with this <code>WSUsernameTokenPrincipal</code>
     * for equality.  Returns true if the given object is also a
     * <code>WSUsernameTokenPrincipal</code> and the two WSUsernameTokenPrincipals
     * have the same username.
     *
     * @param o Object to be compared for equality with this
     *          <code>WSUsernameTokenPrincipal</code>.
     * @return true if the specified Object is equal equal to this
     *         <code>WSUsernameTokenPrincipal</code>.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (this == o) {
            return true;
        }
        if (!(o instanceof WSUsernameTokenPrincipal)) {
            return false;
        }
        WSUsernameTokenPrincipal that = (WSUsernameTokenPrincipal) o;
        if (this.digest != that.digest) {
            return false;
        }
        if (this.name == null ? that.name != null : !this.name.equals(that.name)) {
            return false;
        }
        if (this.nonce == null ? that.nonce != null : !this.nonce.equals(that.nonce)) {
            return false;
        }
        if (this.password == null ? that.password != null : !this.password.equals(that.password)) {
            return false;
        }
        if (this.createdTime == null ? that.createdTime != null 
            : !this.createdTime.equals(that.createdTime)) {
            return false;
        }
        if (this.passwordType == null ? that.passwordType != null 
            : !this.passwordType.equals(that.passwordType)) {
            return false;
        }
        return true;
    }

    /**
     * Return a hash code for this <code>WSUsernameTokenPrincipal</code>.
     *
     * @return a hash code for this <code>WSUsernameTokenPrincipal</code>.
     */
    @Override
    public int hashCode() {
        int hashcode = 17;
        hashcode = 31 * hashcode + (digest ? 1 : 0);
        hashcode = 31 * hashcode + (name == null ? 0 : name.hashCode());
        hashcode = 31 * hashcode + (nonce == null ? 0 : nonce.hashCode());
        hashcode = 31 * hashcode + (password == null ? 0 : password.hashCode());
        hashcode = 31 * hashcode + (createdTime == null ? 0 : createdTime.hashCode());
        hashcode = 31 * hashcode + (passwordType == null ? 0 : passwordType.hashCode());
        
        return hashcode;
    }
    
}
