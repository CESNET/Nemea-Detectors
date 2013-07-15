<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Loaders
 */



/**
 * Nette auto loader is responsible for loading Nette classes and interfaces.
 *
 * @author     David Grudl
 * @package Nette\Loaders
 */
class NetteLoader extends AutoLoader
{
	/** @var NetteLoader */
	private static $instance;

	/** @var array */
	public $renamed = array(
		'Configurator' => 'Configurator',
		'User' => 'User',
		'DefaultHelpers' => 'TemplateHelpers',
		'LatteException' => 'CompileException',
	);

	/** @var array */
	public $list = array(
		'AbortException' => '/Application/exceptions',
		'Annotation' => '/Reflection/Annotation',
		'AnnotationsParser' => '/Reflection/AnnotationsParser',
		'AppForm' => '/Application/UI/Form',
		'Application' => '/Application/Application',
		'ApplicationException' => '/Application/exceptions',
		'ArgumentOutOfRangeException' => '/common/exceptions',
		'ArrayHash' => '/common/ArrayHash',
		'ArrayList' => '/common/ArrayList',
		'Arrays' => '/Utils/Arrays',
		'AssertionException' => '/Utils/Validators',
		'AuthenticationException' => '/Security/AuthenticationException',
		'AutoLoader' => '/Loaders/AutoLoader',
		'BadRequestException' => '/Application/exceptions',
		'BadSignalException' => '/Application/UI/BadSignalException',
		'Button' => '/Forms/Controls/Button',
		'Cache' => '/Caching/Cache',
		'CacheMacro' => '/Latte/Macros/CacheMacro',
		'CachingHelper' => '/Caching/OutputHelper',
		'Callback' => '/common/Callback',
		'Checkbox' => '/Forms/Controls/Checkbox',
		'ClassReflection' => '/Reflection/ClassType',
		'CliRouter' => '/Application/Routers/CliRouter',
		'CompileException' => '/Latte/exceptions',
		'Component' => '/ComponentModel/Component',
		'ComponentContainer' => '/ComponentModel/Container',
		'ConfigCompiler' => '/Config/Compiler',
		'ConfigCompilerExtension' => '/Config/CompilerExtension',
		'ConfigHelpers' => '/Config/Helpers',
		'ConfigIniAdapter' => '/Config/Adapters/IniAdapter',
		'ConfigLoader' => '/Config/Loader',
		'ConfigNeonAdapter' => '/Config/Adapters/NeonAdapter',
		'ConfigPhpAdapter' => '/Config/Adapters/PhpAdapter',
		'Configurator' => '/Config/Configurator',
		'Connection' => '/Database/Connection',
		'ConstantsExtension' => '/Config/Extensions/ConstantsExtension',
		'ContainerPanel' => '/DI/Diagnostics/ContainerPanel',
		'Control' => '/Application/UI/Control',
		'ConventionalReflection' => '/Database/Reflection/ConventionalReflection',
		'CoreMacros' => '/Latte/Macros/CoreMacros',
		'DIContainer' => '/DI/Container',
		'DIContainerBuilder' => '/DI/ContainerBuilder',
		'DIHelpers' => '/DI/Helpers',
		'DINestedAccessor' => '/DI/NestedAccessor',
		'DIServiceDefinition' => '/DI/ServiceDefinition',
		'DIStatement' => '/DI/Statement',
		'DatabaseHelpers' => '/Database/Helpers',
		'DatabasePanel' => '/Database/Diagnostics/ConnectionPanel',
		'DateTime53' => '/common/DateTime',
		'DebugBar' => '/Diagnostics/Bar',
		'DebugBlueScreen' => '/Diagnostics/BlueScreen',
		'DebugHelpers' => '/Diagnostics/Helpers',
		'Debugger' => '/Diagnostics/Debugger',
		'DefaultBarPanel' => '/Diagnostics/DefaultBarPanel',
		'DefaultFormRenderer' => '/Forms/Rendering/DefaultFormRenderer',
		'DeprecatedException' => '/common/exceptions',
		'DevNullStorage' => '/Caching/Storages/DevNullStorage',
		'DirectoryNotFoundException' => '/common/exceptions',
		'DiscoveredReflection' => '/Database/Reflection/DiscoveredReflection',
		'Environment' => '/common/Environment',
		'ExtensionReflection' => '/Reflection/Extension',
		'FatalErrorException' => '/common/exceptions',
		'FileJournal' => '/Caching/Storages/FileJournal',
		'FileNotFoundException' => '/common/exceptions',
		'FileResponse' => '/Application/Responses/FileResponse',
		'FileStorage' => '/Caching/Storages/FileStorage',
		'FileTemplate' => '/Templating/FileTemplate',
		'Finder' => '/Utils/Finder',
		'FireLogger' => '/Diagnostics/FireLogger',
		'ForbiddenRequestException' => '/Application/exceptions',
		'Form' => '/Forms/Form',
		'FormContainer' => '/Forms/Container',
		'FormControl' => '/Forms/Controls/BaseControl',
		'FormGroup' => '/Forms/ControlGroup',
		'FormMacros' => '/Latte/Macros/FormMacros',
		'ForwardResponse' => '/Application/Responses/ForwardResponse',
		'Framework' => '/common/Framework',
		'FreezableObject' => '/common/FreezableObject',
		'FunctionReflection' => '/Reflection/GlobalFunction',
		'GenericRecursiveIterator' => '/Iterators/Recursor',
		'GroupedTableSelection' => '/Database/Table/GroupedSelection',
		'HiddenField' => '/Forms/Controls/HiddenField',
		'Html' => '/Utils/Html',
		'HtmlNode' => '/Latte/HtmlNode',
		'HttpContext' => '/Http/Context',
		'HttpRequest' => '/Http/Request',
		'HttpRequestFactory' => '/Http/RequestFactory',
		'HttpResponse' => '/Http/Response',
		'HttpUploadedFile' => '/Http/FileUpload',
		'IAnnotation' => '/Reflection/IAnnotation',
		'IAuthenticator' => '/Security/IAuthenticator',
		'IAuthorizator' => '/Security/IAuthorizator',
		'IBarPanel' => '/Diagnostics/IBarPanel',
		'ICacheJournal' => '/Caching/Storages/IJournal',
		'ICacheStorage' => '/Caching/IStorage',
		'IComponent' => '/ComponentModel/IComponent',
		'IComponentContainer' => '/ComponentModel/IContainer',
		'IConfigAdapter' => '/Config/IAdapter',
		'IDIContainer' => '/DI/IContainer',
		'IFileTemplate' => '/Templating/IFileTemplate',
		'IFormControl' => '/Forms/IControl',
		'IFormRenderer' => '/Forms/IFormRenderer',
		'IFreezable' => '/common/IFreezable',
		'IHttpRequest' => '/Http/IRequest',
		'IHttpResponse' => '/Http/IResponse',
		'IIdentity' => '/Security/IIdentity',
		'IMacro' => '/Latte/IMacro',
		'IMailer' => '/Mail/IMailer',
		'IOException' => '/common/exceptions',
		'IPresenter' => '/Application/IPresenter',
		'IPresenterFactory' => '/Application/IPresenterFactory',
		'IPresenterResponse' => '/Application/IResponse',
		'IReflection' => '/Database/IReflection',
		'IRenderable' => '/Application/UI/IRenderable',
		'IResource' => '/Security/IResource',
		'IRole' => '/Security/IRole',
		'IRouter' => '/Application/IRouter',
		'ISessionStorage' => '/Http/ISessionStorage',
		'ISignalReceiver' => '/Application/UI/ISignalReceiver',
		'IStatePersistent' => '/Application/UI/IStatePersistent',
		'ISubmitterControl' => '/Forms/ISubmitterControl',
		'ISupplementalDriver' => '/Database/ISupplementalDriver',
		'ITemplate' => '/Templating/ITemplate',
		'ITranslator' => '/Localization/ITranslator',
		'IUserStorage' => '/Security/IUserStorage',
		'Identity' => '/Security/Identity',
		'Image' => '/common/Image',
		'ImageButton' => '/Forms/Controls/ImageButton',
		'InstanceFilterIterator' => '/Iterators/InstanceFilter',
		'InvalidLinkException' => '/Application/UI/InvalidLinkException',
		'InvalidPresenterException' => '/Application/exceptions',
		'InvalidStateException' => '/common/exceptions',
		'Json' => '/Utils/Json',
		'JsonException' => '/Utils/Json',
		'JsonResponse' => '/Application/Responses/JsonResponse',
		'LatteCompiler' => '/Latte/Compiler',
		'LatteFilter' => '/Latte/Engine',
		'LatteToken' => '/Latte/Token',
		'LimitedScope' => '/Utils/LimitedScope',
		'Link' => '/Application/UI/Link',
		'Logger' => '/Diagnostics/Logger',
		'MacroNode' => '/Latte/MacroNode',
		'MacroSet' => '/Latte/Macros/MacroSet',
		'MacroTokenizer' => '/Latte/MacroTokenizer',
		'Mail' => '/Mail/Message',
		'MailMimePart' => '/Mail/MimePart',
		'MapIterator' => '/Iterators/Mapper',
		'MemberAccessException' => '/common/exceptions',
		'MemcachedStorage' => '/Caching/Storages/MemcachedStorage',
		'MemoryStorage' => '/Caching/Storages/MemoryStorage',
		'MethodReflection' => '/Reflection/Method',
		'MimeTypeDetector' => '/Utils/MimeTypeDetector',
		'MissingServiceException' => '/DI/exceptions',
		'MsSqlDriver' => '/Database/Drivers/MsSqlDriver',
		'MultiSelectBox' => '/Forms/Controls/MultiSelectBox',
		'Multiplier' => '/Application/UI/Multiplier',
		'MySqlDriver' => '/Database/Drivers/MySqlDriver',
		'NCallbackFilterIterator' => '/Iterators/Filter',
		'NRecursiveCallbackFilterIterator' => '/Iterators/RecursiveFilter',
		'Neon' => '/Utils/Neon',
		'NeonEntity' => '/Utils/Neon',
		'NeonException' => '/Utils/Neon',
		'NetteExtension' => '/Config/Extensions/NetteExtension',
		'NetteLoader' => '/Loaders/NetteLoader',
		'Nette_MicroPresenter' => '/Application/MicroPresenter',
		'NotImplementedException' => '/common/exceptions',
		'NotSupportedException' => '/common/exceptions',
		'Object' => '/common/Object',
		'ObjectMixin' => '/common/ObjectMixin',
		'OciDriver' => '/Database/Drivers/OciDriver',
		'OdbcDriver' => '/Database/Drivers/OdbcDriver',
		'Paginator' => '/Utils/Paginator',
		'ParameterReflection' => '/Reflection/Parameter',
		'Parser' => '/Latte/Parser',
		'Permission' => '/Security/Permission',
		'PgSqlDriver' => '/Database/Drivers/PgSqlDriver',
		'PhpClassType' => '/Utils/PhpGenerator/ClassType',
		'PhpExtension' => '/Config/Extensions/PhpExtension',
		'PhpFileStorage' => '/Caching/Storages/PhpFileStorage',
		'PhpHelpers' => '/Utils/PhpGenerator/Helpers',
		'PhpLiteral' => '/Utils/PhpGenerator/PhpLiteral',
		'PhpMethod' => '/Utils/PhpGenerator/Method',
		'PhpParameter' => '/Utils/PhpGenerator/Parameter',
		'PhpProperty' => '/Utils/PhpGenerator/Property',
		'PhpWriter' => '/Latte/PhpWriter',
		'Presenter' => '/Application/UI/Presenter',
		'PresenterComponent' => '/Application/UI/PresenterComponent',
		'PresenterComponentReflection' => '/Application/UI/PresenterComponentReflection',
		'PresenterFactory' => '/Application/PresenterFactory',
		'PresenterRequest' => '/Application/Request',
		'PropertyReflection' => '/Reflection/Property',
		'RadioList' => '/Forms/Controls/RadioList',
		'RecursiveComponentIterator' => '/ComponentModel/RecursiveComponentIterator',
		'RedirectResponse' => '/Application/Responses/RedirectResponse',
		'RegexpException' => '/Utils/Strings',
		'RobotLoader' => '/Loaders/RobotLoader',
		'Route' => '/Application/Routers/Route',
		'RouteList' => '/Application/Routers/RouteList',
		'RoutingDebugger' => '/Application/Diagnostics/RoutingPanel',
		'Row' => '/Database/Row',
		'Rule' => '/Forms/Rule',
		'Rules' => '/Forms/Rules',
		'SafeStream' => '/Utils/SafeStream',
		'SelectBox' => '/Forms/Controls/SelectBox',
		'SendmailMailer' => '/Mail/SendmailMailer',
		'ServiceCreationException' => '/DI/exceptions',
		'Session' => '/Http/Session',
		'SessionSection' => '/Http/SessionSection',
		'SimpleAuthenticator' => '/Security/SimpleAuthenticator',
		'SimpleRouter' => '/Application/Routers/SimpleRouter',
		'SmartCachingIterator' => '/Iterators/CachingIterator',
		'SmtpException' => '/Mail/SmtpMailer',
		'SmtpMailer' => '/Mail/SmtpMailer',
		'SqlBuilder' => '/Database/Table/SqlBuilder',
		'SqlLiteral' => '/Database/SqlLiteral',
		'SqlPreprocessor' => '/Database/SqlPreprocessor',
		'Sqlite2Driver' => '/Database/Drivers/Sqlite2Driver',
		'SqliteDriver' => '/Database/Drivers/SqliteDriver',
		'Statement' => '/Database/Statement',
		'StaticClassException' => '/common/exceptions',
		'Strings' => '/Utils/Strings',
		'SubmitButton' => '/Forms/Controls/SubmitButton',
		'TableRow' => '/Database/Table/ActiveRow',
		'TableSelection' => '/Database/Table/Selection',
		'Template' => '/Templating/Template',
		'TemplateException' => '/Templating/FilterException',
		'TemplateHelpers' => '/Templating/Helpers',
		'TextArea' => '/Forms/Controls/TextArea',
		'TextBase' => '/Forms/Controls/TextBase',
		'TextInput' => '/Forms/Controls/TextInput',
		'TextResponse' => '/Application/Responses/TextResponse',
		'Tokenizer' => '/Utils/Tokenizer',
		'TokenizerException' => '/Utils/Tokenizer',
		'UIMacros' => '/Latte/Macros/UIMacros',
		'UnknownImageFileException' => '/common/Image',
		'UploadControl' => '/Forms/Controls/UploadControl',
		'Url' => '/Http/Url',
		'UrlScript' => '/Http/UrlScript',
		'User' => '/Security/User',
		'UserPanel' => '/Security/Diagnostics/UserPanel',
		'UserStorage' => '/Http/UserStorage',
		'Validators' => '/Utils/Validators',
	);



	/**
	 * Returns singleton instance with lazy instantiation.
	 * @return NetteLoader
	 */
	public static function getInstance()
	{
		if (self::$instance === NULL) {
			self::$instance = new self;
		}
		return self::$instance;
	}



	/**
	 * Handles autoloading of classes or interfaces.
	 * @param  string
	 * @return void
	 */
	public function tryLoad($type)
	{
		$type = ltrim($type, '\\');
		if (isset($this->list[$type])) {
			LimitedScope::load(NETTE_DIR . $this->list[$type] . '.php', TRUE);
			self::$count++;

		}}

}
