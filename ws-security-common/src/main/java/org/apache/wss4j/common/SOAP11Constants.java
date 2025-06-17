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

package org.apache.wss4j.common;

import javax.xml.namespace.QName;

/**
 * SOAP 1.1 constants
 */
public class SOAP11Constants implements SOAPConstants {
    /**
     *
     */
    private static final long serialVersionUID = 3809268485386395322L;
    private static final QName HEADER_QNAME = new QName(WSS4JConstants.URI_SOAP11_ENV, WSS4JConstants.ELEM_HEADER);
    private static final QName BODY_QNAME = new QName(WSS4JConstants.URI_SOAP11_ENV, WSS4JConstants.ELEM_BODY);
    private static final QName ROLE_QNAME = new QName(WSS4JConstants.URI_SOAP11_ENV, WSS4JConstants.ATTR_ACTOR);

    public String getEnvelopeURI() {
        return WSS4JConstants.URI_SOAP11_ENV;
    }

    public QName getHeaderQName() {
        return HEADER_QNAME;
    }

    public QName getBodyQName() {
        return BODY_QNAME;
    }

    /**
     * Obtain the QName for the role attribute (actor/role)
     */
    public QName getRoleAttributeQName() {
        return ROLE_QNAME;
    }

    /**
     * Obtain the "next" role/actor URI
     */
    public String getNextRoleURI() {
        return WSS4JConstants.URI_SOAP11_NEXT_ACTOR;
    }

    /**
     * Obtain the MustUnderstand string
     */
    public String getMustUnderstand() {
        return "1";
    }

}
