backscatter_classifierdatadir=${sysconfdir}/backscatter_classifier/data/
backscatter_classifierobjectsddosdir=${sysconfdir}/backscatter_classifier/objects/ddos/
backscatter_classifierobjectsorganizationdir=${sysconfdir}/backscatter_classifier/objects/organization/
backscatter_classifierdataasndir=${sysconfdir}/backscatter_classifier/data/GeoLite2-ASN_20210330/
backscatter_classifierdatacitydir=${sysconfdir}/backscatter_classifier/data/GeoLite2-City_20210330/

backscatter_classifierdata_DATA=data/backscatter_ddos_model.pickle
backscatter_classifierdataasn_DATA=data/GeoLite2-ASN_20210330/GeoLite2-ASN.mmdb
backscatter_classifierdatacity_DATA=data/GeoLite2-City_20210330/GeoLite2-City.mmdb

backscatter_classifierobjectsddos_DATA=objects/ddos/definition.json
backscatter_classifierobjectsorganization_DATA=objects/organization/definition.json
          
bin_SCRIPTS=backscatter_classifier.py run_backscatter_classifier.sh BackscatterDDoSModel.py

EXTRA_DIST=${bin_SCRIPTS} ${backscatter_classifierdata_DATA} ${backscatter_classifierdataasn_DATA} \
          ${backscatter_classifierdatacity_DATA} ${backscatter_classifierobjectsddos_DATA} \
          ${backscatter_classifierobjectsorganization_DATA}

backscatter_classifiersysconfdir=${sysconfdir}/backscatter_classifier/
dist_backscatter_classifiersysconf_DATA=${backscatter_classifierdata_DATA} ${backscatterobjects_DATA}

pkgdocdir=${docdir}/backscatter_classifier
dist_pkgdoc_DATA=README.md