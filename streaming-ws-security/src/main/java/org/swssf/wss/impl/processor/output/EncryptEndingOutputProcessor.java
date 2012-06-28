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
package org.swssf.wss.impl.processor.output;

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.impl.processor.output.AbstractEncryptEndingOutputProcessor;

import javax.xml.stream.XMLStreamException;

/**
 * Processor buffers encrypted XMLEvents and forwards them when final is called
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptEndingOutputProcessor extends AbstractEncryptEndingOutputProcessor {

    public EncryptEndingOutputProcessor() throws XMLSecurityException {
        super();
        this.addAfterProcessor(EncryptOutputProcessor.class.getName());
        this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
        if (getAction() == WSSConstants.ENCRYPT_WITH_DERIVED_KEY) {
            createReferenceListStructure(subOutputProcessorChain);
        }
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
        WSSUtils.flushBufferAndCallbackAfterTokenID(subOutputProcessorChain, this, getXmlSecEventBuffer());
        //call final on the rest of the chain
        subOutputProcessorChain.doFinal();
        //this processor is now finished and we can remove it now
        subOutputProcessorChain.removeProcessor(this);
    }
}
