package ch.gigerstyle.xmlsec;

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

    List<OutputProcessor> outputProcessors = new ArrayList<OutputProcessor>();
    int pos = 0;

    XMLSecurityContext xmlSecurityContext;

    public OutputProcessorChainImpl() {
        xmlSecurityContext = new XMLSecurityContext();
    }

    public int getPos() {
        return pos;
    }

    public void setPos(int pos) {
        this.pos = pos;
    }

    public int getPosAndIncrement() {
        /*
        if (this.pos >= outputProcessors.size()) {
            this.pos = 0;
        }
        System.out.println("Main chain increment" + this.pos);
        */
        return this.pos++;
    }

    public void reset() {
        setPos(0);
    }

    public SecurityContext getSecurityContext() {
        return this.xmlSecurityContext;
    }

    public void addProcessor(OutputProcessor outputProcessor) {
        if (outputProcessor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.EncryptOutputProcessor$InternalEncryptionOutputProcessor")) {
            int pos = this.outputProcessors.size() - 1;
            for (int i = 0; i < outputProcessors.size(); i++) {
                OutputProcessor processor = outputProcessors.get(i);
                if (processor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.EncryptOutputProcessor$InternalEncryptionOutputProcessor")) {
                    //add encrypption processor before other encryption processors...
                    pos = i;
                    break;
                }
            }
            System.out.println("Adding internal enc proc at pos " + pos);
            this.outputProcessors.add(pos, outputProcessor);
        }
        else if (outputProcessor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.SignatureOutputProcessor$InternalSignatureOutputProcessor")) {
            int pos = this.outputProcessors.size() - 1;
            for (int i = 0; i < outputProcessors.size(); i++) {
                OutputProcessor processor = outputProcessors.get(i);
                if (processor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.SignatureOutputProcessor")) {
                    //add encrypption processor before other encryption processors...
                    pos = i + 1;
                    break;
                }
            }
            this.outputProcessors.add(pos, outputProcessor);
            System.out.println("Adding internal sig proc at pos " + pos);
        }
        else if (outputProcessor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.BinarySecurityTokenOutputProcessor")) {
            this.outputProcessors.add(this.outputProcessors.size() - 1, outputProcessor);
            System.out.println("Adding internal bst proc at pos " + (this.outputProcessors.size() - 1));
        }
        else if (outputProcessor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.SignatureOutputProcessor$SignedInfoProcessor")) {
            int pos = this.outputProcessors.size() - 1;
            for (int i = 0; i < outputProcessors.size(); i++) {
                OutputProcessor processor = outputProcessors.get(i);
                if (processor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.output.SignatureOutputProcessor")) {
                    //add encrypption processor before other encryption processors...
                    pos = i + 1;
                    break;
                }
            }
            this.outputProcessors.add(pos, outputProcessor);
            System.out.println("Adding internal bst proc at pos " + (this.outputProcessors.size() - 1));
        }
        else {
            this.outputProcessors.add(outputProcessor);
        }
        /*
        for (int i = 0; i < outputProcessors.size(); i++) {
            System.out.println("New Processor Chain: pos: " + i + " name: " + outputProcessors.get(i).getClass().getName());
        }
        */
    }

    public void removeProcessor(OutputProcessor outputProcessor) {
        if (this.outputProcessors.indexOf(outputProcessor) <= getPos()) {
            this.pos--;
        }
        
        //System.out.println("Removing proc " + outputProcessor.getClass().getName() + " from pos " + outputProcessors.indexOf(outputProcessor));
        this.outputProcessors.remove(outputProcessor);
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(getPosAndIncrement()).processNextEvent(xmlEvent, this, xmlSecurityContext);
    }

    public void processHeaderEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(getPosAndIncrement()).processNextHeaderEvent(xmlEvent, this, xmlSecurityContext);
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
            this.xmlSecurityContext = securityContext;
            this.startPos = this.pos = pos;
            //we don't clone the list to get updates in the sublist too!
            this.outputProcessors = outputProcessors;
        }        

        public void reset() {
            this.pos = startPos;
        }
    }
}
