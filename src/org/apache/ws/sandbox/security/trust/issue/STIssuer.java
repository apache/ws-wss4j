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
package org.apache.ws.security.trust.issue;

import org.w3c.dom.Document;

/**
 * @author Malinda Kaushalye
 *
 * Builds the response message to issue a token.
 * any class that implements <code>STIssuer</code> would have the freedom to 
 * define its own way of issuing (i.e constructing the response) tokens
 */
public interface STIssuer {
	public Document issue(Document req,Document res)throws Exception;
}
