<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Application\Diagnostics
 */



/**
 * Routing debugger for Debug Bar.
 *
 * @author     David Grudl
 * @package Nette\Application\Diagnostics
 */
class RoutingDebugger extends Object implements IBarPanel
{
	/** @var IRouter */
	private $router;

	/** @var IHttpRequest */
	private $httpRequest;

	/** @var array */
	private $routers = array();

	/** @var PresenterRequest */
	private $request;



	public static function initializePanel(Application $application)
	{
		Debugger::$blueScreen->addPanel(create_function('$e', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('application'=>$application)).'-1], EXTR_REFS);
			return $e ? NULL : array(
				\'tab\' => \'Nette Application\',
				\'panel\' => \'<h3>Requests</h3>\' . DebugHelpers::clickableDump($application->getRequests())
					. \'<h3>Presenter</h3>\' . DebugHelpers::clickableDump($application->getPresenter())
			);
		'));
	}



	public function __construct(IRouter $router, IHttpRequest $httpRequest)
	{
		$this->router = $router;
		$this->httpRequest = $httpRequest;
	}



	/**
	 * Renders tab.
	 * @return string
	 */
	public function getTab()
	{
		$this->analyse($this->router);
		ob_start();
		require dirname(__FILE__) . '/templates/RoutingPanel.tab.phtml';
		return ob_get_clean();
	}



	/**
	 * Renders panel.
	 * @return string
	 */
	public function getPanel()
	{
		ob_start();
		require dirname(__FILE__) . '/templates/RoutingPanel.panel.phtml';
		return ob_get_clean();
	}



	/**
	 * Analyses simple route.
	 * @param  IRouter
	 * @return void
	 */
	private function analyse($router, $module = '')
	{
		if ($router instanceof RouteList) {
			foreach ($router as $subRouter) {
				$this->analyse($subRouter, $module . $router->getModule());
			}
			return;
		}

		$matched = 'no';
		$request = $router->match($this->httpRequest);
		if ($request) {
			$request->setPresenterName($module . $request->getPresenterName());
			$matched = 'may';
			if (empty($this->request)) {
				$this->request = $request;
				$matched = 'yes';
			}
		}

		$this->routers[] = array(
			'matched' => $matched,
			'class' => get_class($router),
			'defaults' => $router instanceof Route || $router instanceof SimpleRouter ? $router->getDefaults() : array(),
			'mask' => $router instanceof Route ? $router->getMask() : NULL,
			'request' => $request,
			'module' => rtrim($module, ':')
		);
	}

}
