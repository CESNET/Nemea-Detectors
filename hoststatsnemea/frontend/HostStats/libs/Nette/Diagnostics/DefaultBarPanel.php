<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Diagnostics
 */



/**
 * IDebugPanel implementation helper.
 *
 * @author     David Grudl
 * @internal
 * @package Nette\Diagnostics
 */
final class DefaultBarPanel extends Object implements IBarPanel
{
	private $id;

	public $data;


	public function __construct($id)
	{
		$this->id = $id;
	}



	/**
	 * Renders HTML code for custom tab.
	 * @return string
	 */
	public function getTab()
	{
		ob_start();
		$data = $this->data;
		if ($this->id === 'time') {
			require dirname(__FILE__) . '/templates/bar.time.tab.phtml';
		} elseif ($this->id === 'memory') {
			require dirname(__FILE__) . '/templates/bar.memory.tab.phtml';
		} elseif ($this->id === 'dumps' && $this->data) {
			require dirname(__FILE__) . '/templates/bar.dumps.tab.phtml';
		} elseif ($this->id === 'errors' && $this->data) {
			require dirname(__FILE__) . '/templates/bar.errors.tab.phtml';
		}
		return ob_get_clean();
	}



	/**
	 * Renders HTML code for custom panel.
	 * @return string
	 */
	public function getPanel()
	{
		ob_start();
		$data = $this->data;
		if ($this->id === 'dumps') {
			require dirname(__FILE__) . '/templates/bar.dumps.panel.phtml';
		} elseif ($this->id === 'errors') {
			require dirname(__FILE__) . '/templates/bar.errors.panel.phtml';
		}
		return ob_get_clean();
	}

}
