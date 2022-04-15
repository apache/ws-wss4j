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

package org.apache.wss4j.common.util;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import jakarta.xml.soap.MessageFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class SOAPUtil {
    public static final String SAMPLE_SOAP_MSG =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<SOAP-ENV:Envelope "
                    + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                    + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                    + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
                    + "<SOAP-ENV:Body>"
                    + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">"
                    + "<value xmlns=\"\">15</value>"
                    + "</add>"
                    + "</SOAP-ENV:Body>"
                    + "</SOAP-ENV:Envelope>";

    private static final org.slf4j.Logger LOG =  org.slf4j.LoggerFactory.getLogger(SOAPUtil.class);

    private static DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    private static MessageFactory saajFactory = null;

    static {
        factory.setNamespaceAware(true);
        try {
            saajFactory = MessageFactory.newInstance();
        } catch (Exception e) {
            LOG.debug("can't create SAAJ MessageFactory", e);
        }
    }

    /**
     * Convert an SOAP Envelope as a String to a org.w3c.dom.Document.
     */
    public static org.w3c.dom.Document toSOAPPart(String xml) throws Exception {
        try (InputStream in = new ByteArrayInputStream(xml.getBytes())) {
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(in);
        }
    }

    /**
     * Convert an SOAP Envelope as an InputStream to a org.w3c.dom.Document.
     */
    public static org.w3c.dom.Document toSOAPPart(InputStream in) throws Exception {
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }


    /**
     * Convert an SOAP Envelope as a String to a jakarta.xml.soap.SOAPPart.
     */
    public static jakarta.xml.soap.SOAPPart toSAAJSOAPPart(String xml) throws Exception {
        try (InputStream in = new ByteArrayInputStream(xml.getBytes())) {
            return saajFactory.createMessage(null, in).getSOAPPart();
        }
    }
	
}
