<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Application\Routers
 */



/**
 * The router broker.
 *
 * @author     David Grudl
 * @property-read string $module
 * @package Nette\Application\Routers
 */
class RouteList extends ArrayList implements IRouter
{
	/** @var array */
	private $cachedRoutes;

	/** @var string */
	private $module;



	public function __construct($module = NULL)
	{
		$this->module = $module ? $module . ':' : '';
	}



	/**
	 * Maps HTTP request to a Request object.
	 * @return PresenterRequest|NULL
	 */
	public function match(IHttpRequest $httpRequest)
	{
		foreach ($this as $route) {
			$appRequest = $route->match($httpRequest);
			if ($appRequest !== NULL) {
				$appRequest->setPresenterName($this->module . $appRequest->getPresenterName());
				return $appRequest;
			}
		}
		return NULL;
	}



	/**
	 * Constructs absolute URL from Request object.
	 * @return string|NULL
	 */
	public function constructUrl(PresenterRequest $appRequest, Url $refUrl)
	{
		if ($this->cachedRoutes === NULL) {
			$routes = array();
			$routes['*'] = array();

			foreach ($this as $route) {
				$presenter = $route instanceof Route ? $route->getTargetPresenter() : NULL;

				if ($presenter === FALSE) {
					continue;
				}

				if (is_string($presenter)) {
					$presenter = strtolower($presenter);
					if (!isset($routes[$presenter])) {
						$routes[$presenter] = $routes['*'];
					}
					$routes[$presenter][] = $route;

				} else {
					foreach ($routes as $id => $foo) {
						$routes[$id][] = $route;
					}
				}
			}

			$this->cachedRoutes = $routes;
		}

		if ($this->module) {
			if (strncasecmp($tmp = $appRequest->getPresenterName(), $this->module, strlen($this->module)) === 0) {
				$appRequest = clone $appRequest;
				$appRequest->setPresenterName(substr($tmp, strlen($this->module)));
			} else {
				return NULL;
			}
		}

		$presenter = strtolower($appRequest->getPresenterName());
		if (!isset($this->cachedRoutes[$presenter])) {
			$presenter = '*';
		}

		foreach ($this->cachedRoutes[$presenter] as $route) {
			$url = $route->constructUrl($appRequest, $refUrl);
			if ($url !== NULL) {
				return $url;
			}
		}

		return NULL;
	}



	/**
	 * Adds the router.
	 * @param  mixed
	 * @param  IRouter
	 * @return void
	 */
	public function offsetSet($index, $route)
	{
		if (!$route instanceof IRouter) {
			throw new InvalidArgumentException("Argument must be IRouter descendant.");
		}
		parent::offsetSet($index, $route);
	}



	/**
	 * @return string
	 */
	public function getModule()
	{
		return $this->module;
	}

}
