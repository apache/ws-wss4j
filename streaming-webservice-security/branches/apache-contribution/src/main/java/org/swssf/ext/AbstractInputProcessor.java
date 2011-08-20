/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Set;

/**
 * An abstract InputProcessor class for reusabilty
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractInputProcessor implements InputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    private SecurityProperties securityProperties;

    private Constants.Phase phase = Constants.Phase.PROCESSING;
    private Set<Object> beforeProcessors = new HashSet<Object>();
    private Set<Object> afterProcessors = new HashSet<Object>();

    public AbstractInputProcessor(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public Constants.Phase getPhase() {
        return phase;
    }

    public void setPhase(Constants.Phase phase) {
        this.phase = phase;
    }

    public Set<Object> getBeforeProcessors() {
        return beforeProcessors;
    }

    public Set<Object> getAfterProcessors() {
        return afterProcessors;
    }

    public abstract XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException;

    public abstract XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException;

    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        inputProcessorChain.doFinal();
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }
}
