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
package org.swssf.xmlsec.ext;

import javax.xml.stream.events.XMLEvent;

/**
 * Parseable interface to parse and validate xml
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface Parseable {

    /**
     * @param xmlEvent The XMLEvent to parse
     * @return true when current Element is finished
     * @throws ParseException in the case of an unexpected element
     */
    public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException;

    /**
     * Validates the XML-Object structure
     *
     * @throws ParseException thrown when the the object-structure is invalid
     */
    public void validate() throws ParseException;
}
