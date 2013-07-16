<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Latte\Macros
 */



/**
 * Macro {cache} ... {/cache}
 *
 * @author     David Grudl
 * @package Nette\Latte\Macros
 */
class CacheMacro extends Object implements IMacro
{
	/** @var bool */
	private $used;



	/**
	 * Initializes before template parsing.
	 * @return void
	 */
	public function initialize()
	{
		$this->used = FALSE;
	}



	/**
	 * Finishes template parsing.
	 * @return array(prolog, epilog)
	 */
	public function finalize()
	{
		if ($this->used) {
			return array('CacheMacro::initRuntime($template, $_g);');
		}
	}



	/**
	 * New node is found.
	 * @return bool
	 */
	public function nodeOpened(MacroNode $node)
	{
		$this->used = TRUE;
		$node->isEmpty = FALSE;
		$node->openingCode = PhpWriter::using($node)
			->write('<?php if (CacheMacro::createCache($netteCacheStorage, %var, $_g->caches, %node.array?)) { ?>',
				Strings::random()
			);
	}



	/**
	 * Node is closed.
	 * @return void
	 */
	public function nodeClosed(MacroNode $node)
	{
		$node->closingCode = '<?php $_l->tmp = array_pop($_g->caches); if (!$_l->tmp instanceof stdClass) $_l->tmp->end(); } ?>';
	}



	/********************* run-time helpers ****************d*g**/



	/**
	 * @return void
	 */
	public static function initRuntime(FileTemplate $template, stdClass $global)
	{
		if (!empty($global->caches)) {
			end($global->caches)->dependencies[Cache::FILES][] = $template->getFile();
		}
	}



	/**
	 * Starts the output cache. Returns CachingHelper object if buffering was started.
	 * @param  ICacheStorage
	 * @param  string
	 * @param  CachingHelper[]
	 * @param  array
	 * @return CachingHelper
	 */
	public static function createCache(ICacheStorage $cacheStorage, $key, & $parents, array $args = NULL)
	{
		if ($args) {
			if (array_key_exists('if', $args) && !$args['if']) {
				return $parents[] = new stdClass;
			}
			$key = array_merge(array($key), array_intersect_key($args, range(0, count($args))));
		}
		if ($parents) {
			end($parents)->dependencies[Cache::ITEMS][] = $key;
		}

		$cache = new Cache($cacheStorage, 'Nette.Templating.Cache');
		if ($helper = $cache->start($key)) {
			if (isset($args['expire'])) {
				$args['expiration'] = $args['expire']; // back compatibility
			}
			$helper->dependencies = array(
				Cache::TAGS => isset($args['tags']) ? $args['tags'] : NULL,
				Cache::EXPIRATION => isset($args['expiration']) ? $args['expiration'] : '+ 7 days',
			);
			$parents[] = $helper;
		}
		return $helper;
	}

}
