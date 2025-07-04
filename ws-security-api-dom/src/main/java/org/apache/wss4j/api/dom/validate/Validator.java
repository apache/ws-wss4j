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

package org.apache.wss4j.api.dom.validate;


import javax.xml.namespace.QName;

import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * This interface describes a pluggable way of validating credentials that have been extracted
 * by the processors.
 */
public interface Validator {

    /**
     * Validate the credential argument. This method returns a Credential instance that
     * represents the validated credential. This instance can be the same as the instance
     * that was validated, or it can represent some transformation of the initial Credential
     * instance.
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @return a validated Credential
     * @throws WSSecurityException on a failed validation
     */
    Credential validate(Credential credential, RequestData data) throws WSSecurityException;

    QName[] getSupportedQNames();

}
