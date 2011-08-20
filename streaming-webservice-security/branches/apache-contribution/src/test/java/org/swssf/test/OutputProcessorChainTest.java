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
package org.swssf.test;

import org.swssf.ext.*;
import org.swssf.impl.OutputProcessorChainImpl;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Set;

public class OutputProcessorChainTest extends AbstractTestBase {

    abstract class AbstractOutputProcessor implements OutputProcessor {

        private Constants.Phase phase = Constants.Phase.PROCESSING;
        private Set<Object> beforeProcessors = new HashSet<Object>();
        private Set<Object> afterProcessors = new HashSet<Object>();

        public Set<Object> getBeforeProcessors() {
            return beforeProcessors;
        }

        public Set<Object> getAfterProcessors() {
            return afterProcessors;
        }

        public Constants.Phase getPhase() {
            return phase;
        }

        public void setPhase(Constants.Phase phase) {
            this.phase = phase;
        }

        public void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        }

        public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        }
    }

    @Test
    public void testAddProcessorPhase1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new SecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor3);

        Assert.assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor1);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor3);
    }

    @Test
    public void testAddProcessorPhase2() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new SecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor6);

        Assert.assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor2);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor5);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor1);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor3);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }

    @Test
    public void testAddProcessorBefore1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new SecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessor4.getBeforeProcessors().add(outputProcessor3.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessor5.getBeforeProcessors().add(outputProcessor2.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.getBeforeProcessors().add(outputProcessor1.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor6);

        Assert.assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor5);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor6);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor1);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor4);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor3);
    }

    @Test
    public void testAddProcessorAfter1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new SecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        outputProcessor4.getAfterProcessors().add(outputProcessor3.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        outputProcessor5.getAfterProcessors().add(outputProcessor2.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.getAfterProcessors().add(outputProcessor1.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor6);

        Assert.assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor2);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor5);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor1);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor3);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }

    @Test
    public void testAddProcessorBeforeAndAfter1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new SecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.getBeforeProcessors().add("");
        outputProcessor5.getAfterProcessors().add(outputProcessor3.getClass().getName());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.getBeforeProcessors().add(outputProcessor5.getClass().getName());
        outputProcessor6.getAfterProcessors().add("");
        outputProcessorChain.addProcessor(outputProcessor6);

        Assert.assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor1);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor3);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor5);
        Assert.assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }
}
