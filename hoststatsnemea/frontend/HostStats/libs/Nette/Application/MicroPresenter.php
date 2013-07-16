<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package NetteModule
 */



/**
 * Micro presenter.
 *
 * @author     David Grudl
 *
 * @property-read IRequest $request
 * @package NetteModule
 */
class Nette_MicroPresenter extends Object implements IPresenter
{
	/** @var DIContainer */
	private $context;

	/** @var PresenterRequest */
	private $request;



	public function __construct(DIContainer $context)
	{
		$this->context = $context;
	}



	/**
	 * Gets the context.
	 * @return SystemContainer|DIContainer
	 */
	final public function getContext()
	{
		return $this->context;
	}



	/**
	 * @return IPresenterResponse
	 */
	public function run(PresenterRequest $request)
	{
		$this->request = $request;

		$httpRequest = $this->context->getByType('IHttpRequest');
		if (!$httpRequest->isAjax() && ($request->isMethod('get') || $request->isMethod('head'))) {
			$refUrl = clone $httpRequest->getUrl();
			$url = $this->context->router->constructUrl($request, $refUrl->setPath($refUrl->getScriptPath()));
			if ($url !== NULL && !$httpRequest->getUrl()->isEqual($url)) {
				return new RedirectResponse($url, IHttpResponse::S301_MOVED_PERMANENTLY);
			}
		}

		$params = $request->getParameters();
		if (!isset($params['callback'])) {
			throw new BadRequestException("Parameter callback is missing.");
		}
		$params['presenter'] = $this;
		$callback = new Callback($params['callback']);
		$response = $callback->invokeArgs(PresenterComponentReflection::combineArgs($callback->toReflection(), $params));

		if (is_string($response)) {
			$response = array($response, array());
		}
		if (is_array($response)) {
			if ($response[0] instanceof SplFileInfo) {
				$response = $this->createTemplate('FileTemplate')
					->setParameters($response[1])->setFile($response[0]);
			} else {
				$response = $this->createTemplate('Template')
					->setParameters($response[1])->setSource($response[0]);
			}
		}
		if ($response instanceof ITemplate) {
			return new TextResponse($response);
		} else {
			return $response;
		}
	}



	/**
	 * Template factory.
	 * @param  string
	 * @param  callable
	 * @return ITemplate
	 */
	public function createTemplate($class = NULL, $latteFactory = NULL)
	{
		$template = $class ? new $class : new FileTemplate;

		$template->setParameters($this->request->getParameters());
		$template->presenter = $this;
		$template->context = $context = $this->context;
		$url = $context->getByType('IHttpRequest')->getUrl();
		$template->baseUrl = rtrim($url->getBaseUrl(), '/');
		$template->basePath = rtrim($url->getBasePath(), '/');

		$template->registerHelperLoader('TemplateHelpers::loader');
		$template->setCacheStorage($context->nette->templateCacheStorage);
		$template->onPrepareFilters[] = create_function('$template', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('latteFactory'=>$latteFactory,'context'=> $context)).'-1], EXTR_REFS);
			$template->registerFilter($latteFactory ? $latteFactory() : new LatteFilter);
		');
		return $template;
	}



	/**
	 * Redirects to another URL.
	 * @param  string
	 * @param  int HTTP code
	 * @return void
	 */
	public function redirectUrl($url, $code = IHttpResponse::S302_FOUND)
	{
		return new RedirectResponse($url, $code);
	}



	/**
	 * Throws HTTP error.
	 * @param  string
	 * @param  int HTTP error code
	 * @return void
	 * @throws BadRequestException
	 */
	public function error($message = NULL, $code = IHttpResponse::S404_NOT_FOUND)
	{
		throw new BadRequestException($message, $code);
	}



	/**
	 * @return IRequest
	 */
	public function getRequest()
	{
		return $this->request;
	}

}
