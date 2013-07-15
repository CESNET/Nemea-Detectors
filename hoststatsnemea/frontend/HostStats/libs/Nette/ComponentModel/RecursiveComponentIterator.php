<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\ComponentModel
 */



/**
 * Recursive component iterator. See ComponentContainer::getComponents().
 *
 * @author     David Grudl
 * @internal
 * @package Nette\ComponentModel
 */
class RecursiveComponentIterator extends RecursiveArrayIterator implements Countable
{

	/**
	 * Has the current element has children?
	 * @return bool
	 */
	public function hasChildren()
	{
		return $this->current() instanceof IComponentContainer;
	}



	/**
	 * The sub-iterator for the current element.
	 * @return RecursiveIterator
	 */
	public function getChildren()
	{
		return $this->current()->getComponents();
	}



	/**
	 * Returns the count of elements.
	 * @return int
	 */
	public function count()
	{
		return iterator_count($this);
	}

}
