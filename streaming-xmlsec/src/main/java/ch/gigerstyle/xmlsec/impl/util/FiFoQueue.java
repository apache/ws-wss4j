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

    public FiFoNode<T> getHead() {
        return head;
    }

    public FiFoNode<T> getTail() {
        return tail;
    }

    // Put a new element in the queue

    public void enqueue(T element) {
        FiFoNode<T> newTail = new FiFoNode();
        newTail.value = element;

        if (tail == null) {
            head = tail = newTail;
            return;
        }

        newTail.prev = tail;
        tail.next = newTail;
        tail = newTail;
    }

    /* head      prev <-> next     tail
    |---------------------------------|
    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | ... |
    |_________________________________|
    first                         last                          
     */

    // Get the element from the queue that is in front

    public T dequeue() {
        FiFoNode<T> oldhead = head;
        head = head.next;
        if (head != null) {
            head.prev = null;
        } else {
            tail = head = null;
        }
        return oldhead.value;
    }

    // Check if the queue is empty

    public boolean isEmpty() {
        return head == null;
    }

    // Empty the queue

    public void empty() {
        head = tail = null;
    }

    public class FiFoNode<T> {
        FiFoNode next;
        FiFoNode prev;
        T value;

        FiFoNode() {
        }

        public FiFoNode<T> getNext() {
            return next;
        }

        public FiFoNode<T> getPrev() {
            return prev;
        }

        public T getValue() {
            return value;
        }
    }
}
