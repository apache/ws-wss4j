package ch.gigerstyle.xmlsec.impl.util;

/**
 * User: giger
 * Date: Aug 4, 2010
 * Time: 9:12:13 PM
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
public class FiFoQueue<T> {

    private FiFoNode head = null;
    private FiFoNode tail = null;

    public FiFoQueue() {
    }

    // Put a new elemnt in the queue

    public void enqueue(T element) {
        FiFoNode newNode = new FiFoNode();
        newNode.value = element;

        if (tail != null) {
            tail.next = newNode;
        }
        tail = newNode;

        if (head == null) {
            head = newNode;
        }
    }

    // Get the element from the queue that is in front

    public T dequeue() {
        FiFoNode temp = head;
        head = head.next;
        return temp.value;
    }

    // Check if the queue is empty

    public boolean isEmpty() {
        return head == null;
    }

    // Empty the queue

    public void empty() {
        head = tail = null;
    }

    class FiFoNode {
        FiFoNode next;
        T value;

        FiFoNode() {
        }
    }
}
