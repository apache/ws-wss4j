package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.impl.util.FiFoQueue;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * User: giger
 * Date: Oct 13, 2010
 * Time: 9:11:09 PM
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
public class FiFoQueueTest {

    @Test
    public void testEnDeQueue() throws Exception {
        FiFoQueue<Integer> fiFoQueue = new FiFoQueue<Integer>();

        Assert.assertTrue(fiFoQueue.isEmpty());

        for (int i = 0; i < 10; i++) {
            fiFoQueue.enqueue(i);
        }

        Assert.assertFalse(fiFoQueue.isEmpty());

        for (int i = 0; i < 10; i++) {
            Integer j = fiFoQueue.dequeue();
            Assert.assertEquals(j, (Integer)i);
        }

        Assert.assertTrue(fiFoQueue.isEmpty());
    }

    @Test
    public void testChain() throws Exception {
        FiFoQueue<Integer> fiFoQueue = new FiFoQueue<Integer>();

        Assert.assertTrue(fiFoQueue.isEmpty());

        for (int i = 0; i < 10; i++) {
            fiFoQueue.enqueue(i);
        }

        Assert.assertFalse(fiFoQueue.isEmpty());

        int i = 0;
        FiFoQueue<Integer>.FiFoNode<Integer> fiFoNode = fiFoQueue.getHead();
        while (fiFoNode != null) {
            Assert.assertEquals(fiFoNode.getValue(), (Integer)i++);
            fiFoNode = fiFoNode.getNext();
        }

        Assert.assertEquals(i, 10);
        i--;
        fiFoNode = fiFoQueue.getTail();
        while (fiFoNode != null) {
            Assert.assertEquals(fiFoNode.getValue(), (Integer)i--);
            fiFoNode = fiFoNode.getPrev();
        }

        Assert.assertEquals(i, -1);
    }
}
