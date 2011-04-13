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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.*;

/**
 * Implementation of a OutputProcessorChain
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
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
        if (this.outputProcessors.indexOf(outputProcessor) <= getCurPos()) {
            this.curPos--;
        }
        this.outputProcessors.remove(outputProcessor);
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, WSSecurityException {
        if (this.curPos == this.startPos) {
            xmlEvent = createXMLEventNS(xmlEvent);
            if (xmlEvent.isStartElement()) {
                getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
            } else if (xmlEvent.isEndElement()) {
                getDocumentContext().removePathElement();
            }
        }
        outputProcessors.get(getPosAndIncrement()).processNextEvent(xmlEvent, this);
    }

    public void doFinal() throws XMLStreamException, WSSecurityException {
        outputProcessors.get(getPosAndIncrement()).doFinal(this);
    }

    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, WSSecurityException {
        //we don't clone the processor-list to get updates in the sublist too!
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(securityContext, documentContext.clone(),
                outputProcessors.indexOf(outputProcessor) + 1);
        outputProcessorChain.setOutputProcessors(this.outputProcessors);
        outputProcessorChain.setNsStack(getNsStack());
        outputProcessorChain.setAttrStack(getAttrStack());
        return outputProcessorChain;
    }

    private XMLEvent createXMLEventNS(XMLEvent xmlEvent) {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            QName startElementName = startElement.getName();

            List<String> prefixList = new LinkedList<String>();
            prefixList.add(startElementName.getPrefix());

            List<ComparableNamespace> comparableNamespaceList = new LinkedList<ComparableNamespace>();

            ComparableNamespace curElementNamespace = new ComparableNamespace(startElementName.getPrefix(), startElementName.getNamespaceURI());
            comparableNamespaceList.add(curElementNamespace);

            Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
            while (namespaceIterator.hasNext()) {
                Namespace namespace = namespaceIterator.next();
                String prefix = namespace.getPrefix();

                if (prefix != null && prefix.length() == 0 && namespace.getNamespaceURI().length() == 0) {
                    continue;
                }

                if (!prefixList.contains(prefix)) {
                    prefixList.add(prefix);
                    ComparableNamespace tmpNameSpace = new ComparableNamespace(prefix, namespace.getNamespaceURI());
                    comparableNamespaceList.add(tmpNameSpace);
                }
            }

            List<ComparableAttribute> comparableAttributeList = new LinkedList<ComparableAttribute>();

            Iterator<Attribute> attributeIterator = startElement.getAttributes();
            while (attributeIterator.hasNext()) {
                Attribute attribute = attributeIterator.next();
                String prefix = attribute.getName().getPrefix();

                if (prefix != null && prefix.length() == 0 && attribute.getName().getNamespaceURI().length() == 0) {
                    continue;
                }
                if ("xml".equals(prefix)) {
                    continue;
                }

                comparableAttributeList.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));

                //does an attribute have an namespace?
                if (!prefixList.contains(prefix)) {
                    prefixList.add(prefix);
                    ComparableNamespace tmpNameSpace = new ComparableNamespace(prefix, attribute.getName().getNamespaceURI());
                    comparableNamespaceList.add(tmpNameSpace);
                }
            }

            nsStack.push(comparableNamespaceList);
            attrStack.push(comparableAttributeList);

            return new XMLEventNS(xmlEvent, nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
        } else if (xmlEvent.isEndElement()) {
            nsStack.pop();
            attrStack.pop();
        }
        return xmlEvent;
    }
}
