wairulesdir=${WAIDETECTORDATADIR}/rules
waidatadir=${WAIDETECTORDATADIR}/data
wairules_DATA=rules/request-application-attack-lfi.data \
	      rules/request-application-attack-php.data \
	      rules/request-application-attack-rce.data \
	      rules/request-application-attack-rfi.data \
	      rules/request-application-attack-session-fixation.data \
	      rules/request-application-attack-sqli.data \
	      rules/request-application-attack-xss.data \
	      rules/request-method-enforcement.data \
	      rules/request-protocol-attack.data \
	      rules/request-protocol-enforcement.data \
	      rules/request-scanner-detection.data

waidata_DATA=data/allowed-http-methods.data \
	     data/lfi-os-files.data \
	     data/php-config-directives.data \
	     data/php-function-names-933150.data \
	     data/php-variables.data \
	     data/restricted-files.data \
	     data/scanners-headers.data \
	     data/scanners-urls.data \
	     data/scanners-user-agents.data \
	     data/unix-shell.data \
	     data/windows-powershell-commands.data

bin_SCRIPTS=waintrusion_detector.py waintrusion_detector2idea.py

EXTRA_DIST=waintrusion_detector2idea.py ${wairules_DATA} ${waidata_DATA}

pkgdocdir=${docdir}/waintrusion
dist_pkgdoc_DATA=README.md

