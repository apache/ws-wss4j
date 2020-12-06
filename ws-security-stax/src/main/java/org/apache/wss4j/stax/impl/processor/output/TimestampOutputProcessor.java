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
package org.apache.wss4j.stax.impl.processor.output;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

public class TimestampOutputProcessor extends AbstractOutputProcessor {

    public TimestampOutputProcessor() throws XMLSecurityException {
        super();
        addBeforeProcessor(WSSSignatureOutputProcessor.class);
        addBeforeProcessor(EncryptOutputProcessor.class);
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
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {

        outputProcessorChain.processEvent(xmlSecEvent);

        if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

            final QName headerElementName = WSSConstants.TAG_WSU_TIMESTAMP;
            OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

            Instant created = Instant.now();

            int ttl = ((WSSSecurityProperties) getSecurityProperties()).getTimestampTTL();
            Instant expires = created.plusSeconds(ttl);

            OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
            //wsu:id is optional and will be added when signing...
            createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, true, null);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_CREATED, false, null);
            DateTimeFormatter formatter = DateUtil.getDateTimeFormatter(true);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, created.atZone(ZoneOffset.UTC).format(formatter));
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_CREATED);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_EXPIRES, false, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, expires.atZone(ZoneOffset.UTC).format(formatter));
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_EXPIRES);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);

            outputProcessorChain.removeProcessor(this);
        }
    }
}
