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
 * Provides functionality required by all components.
 *
 * @author     David Grudl
 * @package Nette\ComponentModel
 */
interface IComponent
{
	/** Separator for component names in path concatenation. */
	const NAME_SEPARATOR = '-';

	/**
	 * @return string
	 */
	function getName();

	/**
	 * Returns the container if any.
	 * @return IComponentContainer|NULL
	 */
	function getParent();

	/**
	 * Sets the parent of this component.
	 * @param  IComponentContainer
	 * @param  string
	 * @return void
	 */
	function setParent(IComponentContainer $parent = NULL, $name = NULL);

}
