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
package org.swssf.xmlsec.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of a OutputProcessorChain
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class OutputProcessorChainImpl implements OutputProcessorChain {

    protected static final transient Log log = LogFactory.getLog(OutputProcessorChainImpl.class);

    private List<OutputProcessor> outputProcessors = Collections.synchronizedList(new ArrayList<OutputProcessor>());
    private int startPos = 0;
    private int curPos = 0;

    private ArrayDeque<List<ComparableNamespace>> nsStack = new ArrayDeque<List<ComparableNamespace>>(10);
    private ArrayDeque<List<ComparableAttribute>> attrStack = new ArrayDeque<List<ComparableAttribute>>(10);

    private SecurityContext securityContext;
    private DocumentContextImpl documentContext;

    public OutputProcessorChainImpl(SecurityContext securityContext) {
        this(securityContext, 0);
    }

    public OutputProcessorChainImpl(SecurityContext securityContext, int startPos) {
        this(securityContext, new DocumentContextImpl(), startPos);
    }

    public OutputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContext) {
        this(securityContext, documentContext, 0);
    }

    protected OutputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContextImpl, int startPos) {
        this.securityContext = securityContext;
        this.curPos = this.startPos = startPos;
        documentContext = documentContextImpl;
    }

    public int getCurPos() {
        return curPos;
    }

    public void setCurPos(int curPos) {
        this.curPos = curPos;
    }

    public int getPosAndIncrement() {
        return this.curPos++;
    }

    public void reset() {
        setCurPos(startPos);
    }

    public SecurityContext getSecurityContext() {
        return this.securityContext;
    }

    public DocumentContext getDocumentContext() {
        return this.documentContext;
    }

    private void setOutputProcessors(List<OutputProcessor> outputProcessors) {
        this.outputProcessors = outputProcessors;
    }

    private ArrayDeque<List<ComparableNamespace>> getNsStack() {
        return nsStack.clone();
    }

    private void setNsStack(ArrayDeque<List<ComparableNamespace>> nsStack) {
        this.nsStack = nsStack;
    }

    private ArrayDeque<List<ComparableAttribute>> getAttrStack() {
        return attrStack;
    }

    private void setAttrStack(ArrayDeque<List<ComparableAttribute>> attrStack) {
        this.attrStack = attrStack.clone();
    }

    public void addProcessor(OutputProcessor newOutputProcessor) {
        int startPhaseIdx = 0;
        int endPhaseIdx = outputProcessors.size();
        int idxToInsert = endPhaseIdx;
        XMLSecurityConstants.Phase targetPhase = newOutputProcessor.getPhase();

        for (int i = outputProcessors.size() - 1; i >= 0; i--) {
            OutputProcessor outputProcessor = outputProcessors.get(i);
            if (outputProcessor.getPhase().ordinal() < targetPhase.ordinal()) {
                startPhaseIdx = i + 1;
                break;
            }
        }
        for (int i = startPhaseIdx; i < outputProcessors.size(); i++) {
            OutputProcessor outputProcessor = outputProcessors.get(i);
            if (outputProcessor.getPhase().ordinal() > targetPhase.ordinal()) {
                endPhaseIdx = i;
                break;
            }
        }

        //just look for the correct phase and append as last
        if (newOutputProcessor.getBeforeProcessors().isEmpty()
                && newOutputProcessor.getAfterProcessors().isEmpty()) {
            outputProcessors.add(endPhaseIdx, newOutputProcessor);
        } else if (newOutputProcessor.getBeforeProcessors().isEmpty()) {
            idxToInsert = endPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getAfterProcessors().contains(outputProcessor)
                        || newOutputProcessor.getAfterProcessors().contains(outputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    break;
                }
            }
            outputProcessors.add(idxToInsert, newOutputProcessor);
        } else if (newOutputProcessor.getAfterProcessors().isEmpty()) {
            idxToInsert = startPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getBeforeProcessors().contains(outputProcessor)
                        || newOutputProcessor.getBeforeProcessors().contains(outputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    break;
                }
            }
            outputProcessors.add(idxToInsert, newOutputProcessor);
        } else {
            boolean found = false;
            idxToInsert = endPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getBeforeProcessors().contains(outputProcessor)
                        || newOutputProcessor.getBeforeProcessors().contains(outputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    found = true;
                    break;
                }
            }
            if (found) {
                outputProcessors.add(idxToInsert, newOutputProcessor);
            } else {
                for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                    OutputProcessor outputProcessor = outputProcessors.get(i);
                    if (newOutputProcessor.getAfterProcessors().contains(outputProcessor)
                            || newOutputProcessor.getAfterProcessors().contains(outputProcessor.getClass().getName())) {
                        idxToInsert = i + 1;
                        break;
                    }
                }
                outputProcessors.add(idxToInsert, newOutputProcessor);
            }
        }
        if (idxToInsert < this.curPos) {
            this.curPos++;
        }
        if (log.isDebugEnabled()) {
            log.debug("Added " + newOutputProcessor.getClass().getName() + " to output chain: ");
            for (int i = 0; i < outputProcessors.size(); i++) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                log.debug("Name: " + outputProcessor.getClass().getName() + " phase: " + outputProcessor.getPhase());
            }
        }
    }

    public void removeProcessor(OutputProcessor outputProcessor) {
        log.debug("Removing processor " + outputProcessor.getClass().getName() + " from output chain");
        if (this.outputProcessors.indexOf(outputProcessor) <= getCurPos()) {
            this.curPos--;
        }
        this.outputProcessors.remove(outputProcessor);
    }

    public List<OutputProcessor> getProcessors() {
        return this.outputProcessors;
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        if (this.curPos == this.startPos) {
            xmlEvent = XMLSecurityUtils.createXMLEventNS(xmlEvent, nsStack, attrStack);
            if (xmlEvent.isStartElement()) {
                getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
            } else if (xmlEvent.isEndElement()) {
                getDocumentContext().removePathElement();
            }
        }
        outputProcessors.get(getPosAndIncrement()).processNextEvent(xmlEvent, this);
    }

    public void doFinal() throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(getPosAndIncrement()).doFinal(this);
    }

    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException {
        //we don't clone the processor-list to get updates in the sublist too!
        OutputProcessorChainImpl outputProcessorChain = null;
        try {
            outputProcessorChain = new OutputProcessorChainImpl(securityContext, documentContext.clone(),
                    outputProcessors.indexOf(outputProcessor) + 1);
        } catch (CloneNotSupportedException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
        }
        outputProcessorChain.setOutputProcessors(this.outputProcessors);
        outputProcessorChain.setNsStack(getNsStack());
        outputProcessorChain.setAttrStack(getAttrStack());
        return outputProcessorChain;
    }
}
