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
package org.swssf.policy;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyConstants {

    public static final String NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";

    public static final String PREFIX_SOAPENV = "env";
    public static final String TAG_soap_Body_LocalName = "Body";

    public static final QName TAG_soap11_Body = new QName(NS_SOAP11, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Body = new QName(NS_SOAP12, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
}
