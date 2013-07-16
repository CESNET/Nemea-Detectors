<?php



/**
 * Router factory.
 */
class RouterFactory
{

	/**
	 * @return IRouter
	 */
	public function createRouter()
	{
		$router = new RouteList();
		if (Environment::getHttpRequest()->isSecured())
			$flag = SimpleRouter::SECURED;
		else
			$flag = null;
		$router[] = new SimpleRouter('Overview:default', $flag);
		//$router[] = new Route('index.php', 'Homepage:default'/*, Route::ONE_WAY*/);
		//$router[] = new Route('<presenter>/<action>[/<id>]', 'Homepage:default');
		return $router;
	}

}
