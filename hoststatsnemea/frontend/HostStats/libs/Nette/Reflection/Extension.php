<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Reflection
 */



/**
 * Reports information about a extension.
 *
 * @author     David Grudl
 * @package Nette\Reflection
 */
class ExtensionReflection extends ReflectionExtension
{

	public function __toString()
	{
		return 'Extension ' . $this->getName();
	}



	/********************* Reflection layer ****************d*g**/



	public function getClasses()
	{
		$res = array();
		foreach (parent::getClassNames() as $val) {
			$res[$val] = new ClassReflection($val);
		}
		return $res;
	}



	public function getFunctions()
	{
		foreach ($res = parent::getFunctions() as $key => $val) {
			$res[$key] = new FunctionReflection($key);
		}
		return $res;
	}



	/********************* Object behaviour ****************d*g**/



	/**
	 * @return ClassReflection
	 */
	public function getReflection()
	{
		return new ClassReflection($this);
	}



	public function __call($name, $args)
	{
		return ObjectMixin::call($this, $name, $args);
	}



	public function &__get($name)
	{
		return ObjectMixin::get($this, $name);
	}



	public function __set($name, $value)
	{
		return ObjectMixin::set($this, $name, $value);
	}



	public function __isset($name)
	{
		return ObjectMixin::has($this, $name);
	}



	public function __unset($name)
	{
		ObjectMixin::remove($this, $name);
	}

}
