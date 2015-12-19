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
 * This class represents a SubjectLocality.
 */
public class SubjectLocalityBean {

    /** The ipAddress. */
    private String ipAddress;

    /** The DNS Address. */
    private String dnsAddress;

    /**
     * Default constructor explicitly provided since other constructors would
     * prevent its automatic creation.
     */
    public SubjectLocalityBean() {
        //
    }

    /**
     * Constructor for creating a SubjectLocalityBean with ip and dns addresses.
     *
     * @param ipAddress ip address
     * @param dnsAddress dns address
     */
    public SubjectLocalityBean(final String ipAddress, final String dnsAddress) {
        this.ipAddress = ipAddress;
        this.dnsAddress = dnsAddress;
    }

    /**
     * Get the ip address.
     *
     * @return the ipAddress
     */
    public final String getIpAddress() {
        return ipAddress;
    }

    /**
     * Set the ip address.
     *
     * @param ipAddress the ipAddress to set
     */
    public final void setIpAddress(final String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * Get the dns address.
     *
     * @return the dnsAddress
     */
    public final String getDnsAddress() {
        return dnsAddress;
    }

    /**
     * Set the dns address.
     *
     * @param dnsAddress the dnsAddress to set
     */
    public final void setDnsAddress(final String dnsAddress) {
        this.dnsAddress = dnsAddress;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof SubjectLocalityBean)) {
            return false;
        }

        SubjectLocalityBean that = (SubjectLocalityBean) o;

        if (ipAddress == null && that.ipAddress != null) {
            return false;
        } else if (ipAddress != null && !ipAddress.equals(that.ipAddress)) {
            return false;
        }

        if (dnsAddress == null && that.dnsAddress != null) {
            return false;
        } else if (dnsAddress != null && !dnsAddress.equals(that.dnsAddress)) {
            return false;
        }

        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        int result = 0;
        if (ipAddress != null) {
            result = 31 * result + ipAddress.hashCode();
        }
        if (dnsAddress != null) {
            result = 31 * result + dnsAddress.hashCode();
        }

        return result;
    }
}
