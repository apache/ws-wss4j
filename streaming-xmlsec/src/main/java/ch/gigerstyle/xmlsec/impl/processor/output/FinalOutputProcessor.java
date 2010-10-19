package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

/**
 * User: giger
 * Date: May 29, 2010
 * Time: 4:25:26 PM
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
public class FinalOutputProcessor extends AbstractOutputProcessor {

    private OutputStreamWriter outputStreamWriter;

    public FinalOutputProcessor(OutputStream outputStream, SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        outputStreamWriter = new OutputStreamWriter(outputStream);
        setPhase(Constants.Phase.POSTPROCESSING);
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        xmlEvent.writeAsEncodedUnicode(outputStreamWriter);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        try {
            outputStreamWriter.flush();
        } catch (IOException e) {
            throw new XMLSecurityException(e.getMessage(), e);
        }
    }
}
