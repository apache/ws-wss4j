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

package wssec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class SOAPUtil {
    
    private static DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    static {
        factory.setNamespaceAware(true);
    }
    
    /**
     * Convert an SOAP Envelope as a String to a org.w3c.dom.Document.
     */
    public static org.w3c.dom.Document toSOAPPart(String xml) throws Exception {
        InputStream in = new ByteArrayInputStream(xml.getBytes());
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }
    
}
