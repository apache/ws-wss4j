/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.trust.validate;

import org.w3c.dom.Document;

/**
 * @author Malinda Kaushalye
 *
 * Builds the response message to validate the request
 */
public interface STValidator {
    /**
     * Status of the token as specified in the specification
     */
    public static final String VALID= "http://schemas.xmlsoap.org/ws/2004/04/security/trust/status/valid";
    public static final String INVALID= "http://schemas.xmlsoap.org/ws/2004/04/security/trust/status/invalid";
    
    public Document validate(Document req,Document res)throws Exception;
}
