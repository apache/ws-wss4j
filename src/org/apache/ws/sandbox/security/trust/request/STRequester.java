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
package org.apache.ws.sandbox.security.trust.request;

import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;

import java.util.Hashtable;

/**
 * @author Malinda Kaushalye
 *         Interface STRequester provide a way to build a request
 *         on behalf of the client.
 */
public interface STRequester {
    /**
     * Modify request according to the given options
     *
     * @param req     full Envelop of the SOAP request as a Dom document
     * @param hashOps all the paramaeters in the .wsdd file as a hash map
     * @return modified request docment.
     * @throws WSTrustException
     */
    public Document request(Document req, Hashtable hashOps) throws WSTrustException;
}
