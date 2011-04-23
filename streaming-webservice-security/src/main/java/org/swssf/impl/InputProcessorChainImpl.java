/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of a InputProcessorChain
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class InputProcessorChainImpl implements InputProcessorChain {

    protected static final transient Log log = LogFactory.getLog(InputProcessorChainImpl.class);

    private List<InputProcessor> inputProcessors = Collections.synchronizedList(new ArrayList<InputProcessor>());
    private int startPos = 0;
    private int curPos = 0;

    private SecurityContext securityContext;
    private DocumentContextImpl documentContext;

    public InputProcessorChainImpl(SecurityContext securityContext) {
        this(securityContext, 0);
    }

    public InputProcessorChainImpl(SecurityContext securityContext, int startPos) {
        this(securityContext, new DocumentContextImpl(), startPos);
    }

    public InputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContext) {
        this(securityContext, documentContext, 0);
    }

    protected InputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContextImpl, int startPos) {
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

    private void setInputProcessors(List<InputProcessor> inputProcessors) {
        this.inputProcessors = inputProcessors;
    }

    public void addProcessor(InputProcessor newInputProcessor) {
        int startPhaseIdx = 0;
        int endPhaseIdx = inputProcessors.size();

        Constants.Phase targetPhase = newInputProcessor.getPhase();

        for (int i = 0; i < inputProcessors.size(); i++) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() <= targetPhase.ordinal()) {
                startPhaseIdx = i;
                break;
            }
        }
        for (int i = inputProcessors.size() - 1; i >= startPhaseIdx; i--) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() < targetPhase.ordinal()) {
                endPhaseIdx = i;
                break;
            }
        }

        //just look for the correct phase and append as last
        if (newInputProcessor.getBeforeProcessors().isEmpty()
                && newInputProcessor.getAfterProcessors().isEmpty()) {
            inputProcessors.add(startPhaseIdx, newInputProcessor);
        } else if (newInputProcessor.getBeforeProcessors().isEmpty()) {
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else if (newInputProcessor.getAfterProcessors().isEmpty()) {
            int idxToInsert = endPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else {
            boolean found = false;
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    found = true;
                    break;
                }
            }
            if (found) {
                inputProcessors.add(idxToInsert, newInputProcessor);
            } else {
                for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                    InputProcessor inputProcessor = inputProcessors.get(i);
                    if (newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                        idxToInsert = i;
                        break;
                    }
                }
                inputProcessors.add(idxToInsert, newInputProcessor);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Added " + newInputProcessor.getClass().getName() + " to input chain: ");
            for (int i = 0; i < inputProcessors.size(); i++) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                log.debug("Name: " + inputProcessor.getClass().getName() + " phase: " + inputProcessor.getPhase());
            }
        }
    }

    public void removeProcessor(InputProcessor inputProcessor) {
        log.debug("Removing processor " + inputProcessor.getClass().getName() + " from input chain");
        if (this.inputProcessors.indexOf(inputProcessor) <= getCurPos()) {
            this.curPos--;
        }
        this.inputProcessors.remove(inputProcessor);
    }

    public List<InputProcessor> getProcessors() {
        return this.inputProcessors;
    }

    public XMLEvent processHeaderEvent() throws XMLStreamException, WSSecurityException {
        return inputProcessors.get(getPosAndIncrement()).processNextHeaderEvent(this);
    }

    public XMLEvent processEvent() throws XMLStreamException, WSSecurityException {
        return inputProcessors.get(getPosAndIncrement()).processNextEvent(this);
    }

    public void doFinal() throws XMLStreamException, WSSecurityException {
        inputProcessors.get(getPosAndIncrement()).doFinal(this);
    }

    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, WSSecurityException {
        //we don't clone the processor-list to get updates in the sublist too!
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(securityContext, documentContext.clone(),
                inputProcessors.indexOf(inputProcessor) + 1);
        inputProcessorChain.setInputProcessors(new ArrayList<InputProcessor>(this.inputProcessors));
        return inputProcessorChain;
    }
}
