package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.processor.input.PipedInputProcessor;
import ch.gigerstyle.xmlsec.securityEvent.OperationSecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: Sep 2, 2010
 * Time: 8:08:51 PM
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
public class PolicyInputProcessor extends AbstractInputProcessor {

    private PolicyEnforcer policyEnforcer;

    private XMLEvent deferredXMLEvent;

    public PolicyInputProcessor(PolicyEnforcer policyEnforcer, SecurityProperties securityProperties) {
        super(securityProperties);
        this.setPhase(Constants.Phase.POSTPROCESSING);
        this.getBeforeProcessors().add(PipedInputProcessor.class.getName());
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement() && getLastStartElementName().equals(Constants.TAG_soap11_Body)) {
            OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent(SecurityEvent.Event.Operation);
            operationSecurityEvent.setOperation(xmlEvent.asStartElement().getName());
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        } else if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(Constants.TAG_soap11_Envelope)) {
            //hold the last XMLEvent back until the policy is verified
            deferredXMLEvent = xmlEvent;
            return;
        }
        inputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        try {
            policyEnforcer.doFinal();
        } catch (PolicyViolationException e) {
            throw new XMLSecurityException(e);
        }
        inputProcessorChain.processEvent(deferredXMLEvent);
        inputProcessorChain.reset();
        inputProcessorChain.doFinal();
    }
}
