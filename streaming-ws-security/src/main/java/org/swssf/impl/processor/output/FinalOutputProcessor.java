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
package org.swssf.impl.processor.output;

import org.swssf.ext.*;

import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.OutputStream;

/**
 * Processor which outputs the XMLEvents to an outputStream
 * This Processor can be extended to allow to write to a StAX writer instead of directly to an output stream
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class FinalOutputProcessor extends AbstractOutputProcessor {

    private XMLEventWriter xmlEventWriter;
    private static final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();

    static {
        xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, false);
    }

    public FinalOutputProcessor(OutputStream outputStream, String encoding, SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
        setPhase(Constants.Phase.POSTPROCESSING);
        try {
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(outputStream, encoding);
        } catch (XMLStreamException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        xmlEventWriter.add(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws WSSecurityException {
        try {
            xmlEventWriter.flush();
            xmlEventWriter.close();
        } catch (XMLStreamException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }
}
