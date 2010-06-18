package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.processorImpl.input.DecryptInputProcessor;
import ch.gigerstyle.xmlsec.processorImpl.input.SignatureReferenceVerifyInputProcessor;

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
public class InputProcessorChainImpl implements InputProcessorChain {

    List<InputProcessor> inputProcessors = new ArrayList<InputProcessor>();
    int pos = 0;

    XMLSecurityContext xmlSecurityContext;

    public InputProcessorChainImpl() {
        xmlSecurityContext = new XMLSecurityContext();
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

    public void addProcessor(InputProcessor inputProcessor) {
        if (inputProcessor.getClass().getName().equals(DecryptInputProcessor.class.getName())
                || inputProcessor.getClass().getName().equals(SignatureReferenceVerifyInputProcessor.class.getName())
                || inputProcessor.getClass().getName().equals("ch.gigerstyle.xmlsec.processorImpl.input.SignatureReferenceVerifyInputProcessor$InternalSignatureReferenceVerifier")) {
            this.inputProcessors.add(this.inputProcessors.size() -2, inputProcessor);
        } else {
            this.inputProcessors.add(inputProcessor);
        }
    }

    public void removeProcessor(InputProcessor inputProcessor) {
        if (this.inputProcessors.indexOf(inputProcessor) <= getPos()) {
            this.pos--;
        }
        //System.out.println("Removing proc " + outputProcessor.getClass().getName() + " from pos " + outputProcessors.indexOf(outputProcessor));
        this.inputProcessors.remove(inputProcessor);
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        inputProcessors.get(getPosAndIncrement()).processNextEvent(xmlEvent, this, xmlSecurityContext);
    }

    public void doFinal() throws XMLStreamException, XMLSecurityException {
        inputProcessors.get(getPosAndIncrement()).doFinal(this, xmlSecurityContext);
    }

    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, XMLSecurityException {
        return new InputProcessorSubChainImpl(inputProcessors.indexOf(inputProcessor) + 1, this.inputProcessors);
    }

    class InputProcessorSubChainImpl extends InputProcessorChainImpl {
        private int startPos;

        InputProcessorSubChainImpl(int pos, List<InputProcessor> inputProcessors) {
            this.startPos = this.pos = pos;
            //we don't clone the list to get updates in the sublist too!
            this.inputProcessors = inputProcessors;
        }

        public void reset() {
            this.pos = startPos;
        }
    }
}
