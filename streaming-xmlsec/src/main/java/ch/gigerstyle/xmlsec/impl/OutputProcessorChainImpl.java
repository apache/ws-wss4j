package ch.gigerstyle.xmlsec.impl;

import ch.gigerstyle.xmlsec.ext.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:46:50 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class OutputProcessorChainImpl implements OutputProcessorChain {

    protected static final transient Log log = LogFactory.getLog(OutputProcessorChainImpl.class);

    List<OutputProcessor> outputProcessors = new ArrayList<OutputProcessor>();
    int pos = 0;

    XMLSecurityContext xmlSecurityContext;

    public OutputProcessorChainImpl() {
        xmlSecurityContext = new XMLSecurityContext();
    }

    public OutputProcessorChainImpl(XMLSecurityContext xmlSecurityContext) {
        this.xmlSecurityContext = xmlSecurityContext;
    }

    public int getPos() {
        return pos;
    }

    public void setPos(int pos) {
        this.pos = pos;
    }

    public int getPosAndIncrement() {
        return this.pos++;
    }

    public void reset() {
        setPos(0);
    }

    public SecurityContext getSecurityContext() {
        return this.xmlSecurityContext;
    }

    public void addProcessor(OutputProcessor newOutputProcessor) {
        int startPhaseIdx = 0;
        int endPhaseIdx = outputProcessors.size();

        Constants.Phase targetPhase = newOutputProcessor.getPhase();

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
            int idxToInsert = endPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getAfterProcessors().contains(outputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    break;
                }
            }
            outputProcessors.add(idxToInsert, newOutputProcessor);
        } else if (newOutputProcessor.getAfterProcessors().isEmpty()) {
            int idxToInsert = startPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getBeforeProcessors().contains(outputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    break;
                }
            }
            outputProcessors.add(idxToInsert, newOutputProcessor);
        } else {
            boolean found = false;
            int idxToInsert = endPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                OutputProcessor outputProcessor = outputProcessors.get(i);
                if (newOutputProcessor.getBeforeProcessors().contains(outputProcessor.getClass().getName())) {
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
                    if (newOutputProcessor.getAfterProcessors().contains(outputProcessor.getClass().getName())) {
                        idxToInsert = i + 1;
                        break;
                    }
                }
                outputProcessors.add(idxToInsert, newOutputProcessor);
            }
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
        if (this.outputProcessors.indexOf(outputProcessor) <= getPos()) {
            this.pos--;
        }

        //System.out.println("Removing proc " + outputProcessor.getClass().getName() + " from pos " + outputProcessors.indexOf(outputProcessor));
        this.outputProcessors.remove(outputProcessor);
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(getPosAndIncrement()).processNextEvent(xmlEvent, this, xmlSecurityContext);
    }

    public void doFinal() throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(getPosAndIncrement()).doFinal(this, xmlSecurityContext);
    }

    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException {
        //System.out.println("Creating subprocessor chain for proc " + outputProcessor.getClass().getName() + " at pos " + (outputProcessors.indexOf(outputProcessor) + 1));
        return new OutputProcessorSubChainImpl(xmlSecurityContext, outputProcessors.indexOf(outputProcessor) + 1, this.outputProcessors);
    }

    class OutputProcessorSubChainImpl extends OutputProcessorChainImpl {
        private int startPos;

        OutputProcessorSubChainImpl(XMLSecurityContext securityContext, int pos, List<OutputProcessor> outputProcessors) {
            super(securityContext);
            this.startPos = this.pos = pos;
            //we don't clone the list to get updates in the sublist too!
            this.outputProcessors = outputProcessors;
        }

        public void reset() {
            this.pos = startPos;
        }
    }
}
