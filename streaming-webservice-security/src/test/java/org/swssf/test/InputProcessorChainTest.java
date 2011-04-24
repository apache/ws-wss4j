package org.swssf.test;

import org.swssf.ext.*;
import org.swssf.impl.InputProcessorChainImpl;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Set;

/**
 * User: giger
 * Date: 4/23/11
 * Time: 2:27 PM
 * Copyright 2011 Marc Giger gigerstyle@gmx.ch
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
public class InputProcessorChainTest extends AbstractTestBase {

    abstract class AbstractInputProcessor implements InputProcessor {

        private Constants.Phase phase = Constants.Phase.PROCESSING;
        private Set<String> beforeProcessors = new HashSet<String>();
        private Set<String> afterProcessors = new HashSet<String>();

        public Set<String> getBeforeProcessors() {
            return beforeProcessors;
        }

        public Set<String> getAfterProcessors() {
            return afterProcessors;
        }

        public Constants.Phase getPhase() {
            return phase;
        }

        public void setPhase(Constants.Phase phase) {
            this.phase = phase;
        }

        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return null;
        }

        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return null;
        }

        public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        }
    }

    @Test
    public void testAddProcessorPhase1() {
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(new SecurityContextImpl());

        AbstractInputProcessor inputProcessor1 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor1);

        AbstractInputProcessor inputProcessor2 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor2);

        AbstractInputProcessor inputProcessor3 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor3);

        Assert.assertEquals(inputProcessorChain.getProcessors().get(0), inputProcessor3);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(1), inputProcessor2);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(2), inputProcessor1);
    }

    @Test
    public void testAddProcessorPhase2() {
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(new SecurityContextImpl());

        AbstractInputProcessor inputProcessor1 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor1);

        AbstractInputProcessor inputProcessor2 = new AbstractInputProcessor() {
        };
        inputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor2);

        AbstractInputProcessor inputProcessor3 = new AbstractInputProcessor() {
        };
        inputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor3);

        AbstractInputProcessor inputProcessor4 = new AbstractInputProcessor() {
        };
        inputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor4);

        AbstractInputProcessor inputProcessor5 = new AbstractInputProcessor() {
        };
        inputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor5);

        AbstractInputProcessor inputProcessor6 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor6);

        Assert.assertEquals(inputProcessorChain.getProcessors().get(0), inputProcessor4);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(1), inputProcessor3);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(2), inputProcessor6);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(3), inputProcessor1);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(4), inputProcessor5);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(5), inputProcessor2);
    }

    @Test
    public void testAddProcessorBefore1() {
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(new SecurityContextImpl());

        AbstractInputProcessor inputProcessor1 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor1);

        AbstractInputProcessor inputProcessor2 = new AbstractInputProcessor() {
        };
        inputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor2);

        AbstractInputProcessor inputProcessor3 = new AbstractInputProcessor() {
        };
        inputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor3);

        AbstractInputProcessor inputProcessor4 = new AbstractInputProcessor() {
        };
        inputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessor4.getBeforeProcessors().add(inputProcessor3.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor4);

        AbstractInputProcessor inputProcessor5 = new AbstractInputProcessor() {
        };
        inputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessor5.getBeforeProcessors().add(inputProcessor2.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor5);

        AbstractInputProcessor inputProcessor6 = new AbstractInputProcessor() {
        };
        inputProcessor6.getBeforeProcessors().add(inputProcessor1.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor6);

        Assert.assertEquals(inputProcessorChain.getProcessors().get(0), inputProcessor3);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(1), inputProcessor4);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(2), inputProcessor1);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(3), inputProcessor6);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(4), inputProcessor2);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(5), inputProcessor5);
    }

    @Test
    public void testAddProcessorAfter1() {
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(new SecurityContextImpl());

        AbstractInputProcessor inputProcessor1 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor1);

        AbstractInputProcessor inputProcessor2 = new AbstractInputProcessor() {
        };
        inputProcessor2.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor2);

        AbstractInputProcessor inputProcessor3 = new AbstractInputProcessor() {
        };
        inputProcessor3.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessorChain.addProcessor(inputProcessor3);

        AbstractInputProcessor inputProcessor4 = new AbstractInputProcessor() {
        };
        inputProcessor4.setPhase(Constants.Phase.POSTPROCESSING);
        inputProcessor4.getAfterProcessors().add(inputProcessor3.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor4);

        AbstractInputProcessor inputProcessor5 = new AbstractInputProcessor() {
        };
        inputProcessor5.setPhase(Constants.Phase.PREPROCESSING);
        inputProcessor5.getAfterProcessors().add(inputProcessor2.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor5);

        AbstractInputProcessor inputProcessor6 = new AbstractInputProcessor() {
        };
        inputProcessor6.getAfterProcessors().add(inputProcessor1.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor6);

        Assert.assertEquals(inputProcessorChain.getProcessors().get(0), inputProcessor4);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(1), inputProcessor3);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(2), inputProcessor6);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(3), inputProcessor1);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(4), inputProcessor5);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(5), inputProcessor2);
    }

    @Test
    public void testAddProcessorBeforeAndAfter1() {
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(new SecurityContextImpl());

        AbstractInputProcessor inputProcessor1 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor1);

        AbstractInputProcessor inputProcessor2 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor2);

        AbstractInputProcessor inputProcessor3 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor3);

        AbstractInputProcessor inputProcessor4 = new AbstractInputProcessor() {
        };
        inputProcessorChain.addProcessor(inputProcessor4);

        AbstractInputProcessor inputProcessor5 = new AbstractInputProcessor() {
        };
        inputProcessor5.getBeforeProcessors().add("");
        inputProcessor5.getAfterProcessors().add(inputProcessor3.getClass().getName());
        inputProcessorChain.addProcessor(inputProcessor5);

        AbstractInputProcessor inputProcessor6 = new AbstractInputProcessor() {
        };
        inputProcessor6.getBeforeProcessors().add(inputProcessor5.getClass().getName());
        inputProcessor6.getAfterProcessors().add("");
        inputProcessorChain.addProcessor(inputProcessor6);

        Assert.assertEquals(inputProcessorChain.getProcessors().get(0), inputProcessor4);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(1), inputProcessor5);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(2), inputProcessor6);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(3), inputProcessor3);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(4), inputProcessor2);
        Assert.assertEquals(inputProcessorChain.getProcessors().get(5), inputProcessor1);
    }
}
