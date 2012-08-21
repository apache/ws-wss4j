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
package org.apache.ws.security.stax.impl.processor.output;

import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TimestampOutputProcessor extends AbstractOutputProcessor {

    public TimestampOutputProcessor() throws XMLSecurityException {
        super();
    }

    /*
    <wsu:Timestamp wsu:Id="Timestamp-1247751600"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                2009-08-31T05:37:57.391Z
            </wsu:Created>
            <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                2009-08-31T05:52:57.391Z
            </wsu:Expires>
        </wsu:Timestamp>
     */

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlSecEvent);
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
            if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                    && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                XMLGregorianCalendar created = WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar());

                GregorianCalendar expiresCalendar = new GregorianCalendar();
                expiresCalendar.add(Calendar.SECOND, ((WSSSecurityProperties) getSecurityProperties()).getTimestampTTL());
                XMLGregorianCalendar expires = WSSConstants.datatypeFactory.newXMLGregorianCalendar(expiresCalendar);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                //wsu:id is optional and will be added when signing...
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Timestamp, true, null);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Created, false, null);
                createCharactersAndOutputAsEvent(subOutputProcessorChain, created.toXMLFormat());
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Created);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Expires, false, null);
                createCharactersAndOutputAsEvent(subOutputProcessorChain, expires.toXMLFormat());
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Expires);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Timestamp);

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
