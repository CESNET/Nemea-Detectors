<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\DI\Diagnostics
 */



/**
 * Dependency injection container panel for Debugger Bar.
 *
 * @author     Patrik Votoček
 * @package Nette\DI\Diagnostics
 */
class ContainerPanel extends Object implements IBarPanel
{
	/** @var DIContainer */
	private $container;



	public function __construct(DIContainer $container)
	{
		if (PHP_VERSION_ID < 50300) {
			throw new NotSupportedException(__CLASS__ . ' requires PHP 5.3 or newer.');
		}
		$this->container = $container;
	}



	/**
	 * Renders tab.
	 * @return string
	 */
	public function getTab()
	{
		ob_start();
		require dirname(__FILE__) . '/templates/ContainerPanel.tab.phtml';
		return ob_get_clean();
	}



	/**
	 * Renders panel.
	 * @return string
	 */
	public function getPanel()
	{
		$services = $this->getContainerProperty('factories');
		$factories = array();
		foreach (ClassReflection::from($this->container)->getMethods() as $method) {
			if (preg_match('#^create(Service)?(.+)\z#', $method->getName(), $m)) {
				$name = str_replace('__', '.', strtolower(substr($m[2], 0, 1)) . substr($m[2], 1));
				if ($m[1]) {
					$services[$name] = $method->getAnnotation('return');
				} elseif ($method->isPublic()) {
					$a = strrpos(".$name", '.');
					$factories[substr($name, 0, $a) . 'create' . ucfirst(substr($name, $a))] = $method->getAnnotation('return');
				}
			}
		}
		ksort($services);
		ksort($factories);
		$container = $this->container;
		$registry = $this->getContainerProperty('registry');

		ob_start();
		require dirname(__FILE__) . '/templates/ContainerPanel.panel.phtml';
		return ob_get_clean();
	}



	private function getContainerProperty($name)
	{
		$prop = ClassReflection::from('DIContainer')->getProperty($name);
		$prop->setAccessible(TRUE);
		return $prop->getValue($this->container);
	}

}
