<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Security\Diagnostics
 */



/**
 * User panel for Debugger Bar.
 *
 * @author     David Grudl
 * @package Nette\Security\Diagnostics
 */
class UserPanel extends Object implements IBarPanel
{
	/** @var User */
	private $user;



	public function __construct(User $user)
	{
		$this->user = $user;
	}



	/**
	 * Renders tab.
	 * @return string
	 */
	public function getTab()
	{
		ob_start();
		require dirname(__FILE__) . '/templates/UserPanel.tab.phtml';
		return ob_get_clean();
	}



	/**
	 * Renders panel.
	 * @return string
	 */
	public function getPanel()
	{
		ob_start();
		require dirname(__FILE__) . '/templates/UserPanel.panel.phtml';
		return ob_get_clean();
	}

}
