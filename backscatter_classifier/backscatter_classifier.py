#!/usr/bin/python3

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
import pytrap
import sys
import pickle
import sklearn
import numpy as np
import argparse
import logging
from socket import gethostbyaddr, herror
from datetime import datetime, timezone, timedelta
import geoip2.database
import geoip2.errors
from ipaddress import IPv4Address, IPv4Network
from BackscatterDDoSModel import DDoSModel

# Supported protocols
TCP = 6
ICMP = 1
PROTO_MAP = {TCP: "TCP", ICMP: "ICMP"}

# Custom exit codes
TRAP_ARGS_ERROR_EXIT = 1
PYTHON_ARGS_ERROR_EXIT = 2
EXIT_FAILURE = 3

# MISP complete analysis code
MISP_ANALYSIS_COMPLETE = 2
# MISP threat level
MISP_THREAT = 2
# MISP distribution community
MISP_DIST = 1
# Derive local timezone
LOCAL_TIMEZONE = datetime.now(timezone(timedelta(0))).astimezone().tzinfo

# Monitored range (virtual telescope) must be same as in backscatter module (backscatter.cpp) in case of change!
CESNET_NET = [
    IPv4Network("146.102.0.0/16"),
    IPv4Network("147.228.0.0/14"),
    IPv4Network("147.251.0.0/16"),
    IPv4Network("147.32.0.0/15"),
    IPv4Network("158.194.0.0/16"),
    IPv4Network("158.196.0.0/16"),
    IPv4Network("160.216.0.0/15"),
    IPv4Network("193.84.116.0/23"),
    IPv4Network("193.84.160.0/20"),
    IPv4Network("193.84.192.0/19"),
    IPv4Network("193.84.32.0/20"),
    IPv4Network("193.84.53.0/24"),
    IPv4Network("193.84.55.0/24"),
    IPv4Network("193.84.56.0/21"),
    IPv4Network("193.84.80.0/22"),
    IPv4Network("195.113.0.0/16"),
    IPv4Network("195.178.64.0/19"),
    IPv4Network("78.128.128.0/17")
]

CESNET_IPS = 0
for net in CESNET_NET:
    CESNET_IPS += net.num_addresses

# Number of IPs CESNET monitors (important for derivation of attack size/intensity)
SCALE_FACTOR = 2**32/CESNET_IPS

class ProtocolNotSupported(Exception):
    """Feature vector was produced by traffic from unsupported protocol"""
    pass


class MissingFeatureAttribute(Exception):
    """Feature vector is missing necessary attributes for prediction"""
    pass


class DDoSClassifier:
    """Load stored ML model, compute derived features, make prediction"""

    def __init__(self, model: DDoSModel, threshold: float):
        """
        :param model: Stored backscatter ML model
        """
        self.model = model
        if threshold <= 0 or threshold >= 1:
            raise RuntimeError("Incorrect threshold value")
        self.threshold = threshold

    def get_feature_vector(self, f_list, rec: pytrap.UnirecTemplate):
        """
        :param f_list: List of tuples (feature name, type of feature - primary/derived)
        :param rec: Basic feature vector
        :return: Complete feature vector with derived features
        """
        feature_vector = []
        for f, t in f_list:
            try:
                if t == self.model.PRIMARY:
                    # Copy primary features
                    feature = getattr(rec, f)
                elif t == self.model.DERIVED:
                    # Compute derived features
                    feature = getattr(DDoSClassifier, f)(rec)
            except AttributeError:
                raise MissingFeatureAttribute("Feature {f} is not supported, incompatible models".format(f=f))
            feature_vector.append(feature)
        return np.array([feature_vector])

    def predict(self, rec: pytrap.UnirecTemplate):
        """
        Predict class of feature vector (DDoS/nonDDos)
        :param rec: Basic feature vector derived from backscatter like flows
        :return: True if vector is predicted to come from DDoS attack (backscatter)
        """
        # Choose right model and predict class of feature vector
        if rec.PROTOCOL == TCP:
            feature_vector = self.get_feature_vector(self.model.tcp_features, rec)
            feature_vector = self.model.tcp_scaler.transform(feature_vector)
            return self.model.tcp_model.predict_proba(feature_vector)[:, self.model.DDOS_CLASS][0] > self.threshold
        elif rec.PROTOCOL == ICMP:
            feature_vector = self.get_feature_vector(self.model.icmp_features, rec)
            feature_vector = self.model.icmp_scaler.transform(feature_vector)
            return self.model.icmp_model.predict_proba(feature_vector)[:, self.model.DDOS_CLASS][0] > self.threshold
        else:
            raise ProtocolNotSupported("Protocol with number {d} is not supported".format(d=rec.PROTOCOL))

    # DERIVED FEATURES

    @staticmethod
    def UNIQUE_DST_IPS_N(rec: pytrap.UnirecTemplate):
        """
        :param rec: Basic feature vector
        :return: Normalized count of unique destination IPs by flow count
        """
        return rec.UNIQUE_DST_IPS / rec.FLOW_COUNT

    @staticmethod
    def UNIQUE_DST_PORTS_N(rec: pytrap.UnirecTemplate):
        """
        :param rec: Basic feature vector
        :return: Normalized count of unique destination ports by flow count
        """
        return rec.UNIQUE_DST_PORTS / rec.FLOW_COUNT

    @staticmethod
    def UNIQUE_SRC_PORTS_N(rec: pytrap.UnirecTemplate):
        """
        :param rec: Basic feature vector
        :return: Normalized count of unique source ports by flow count
        """
        return rec.UNIQUE_SRC_PORTS / rec.FLOW_COUNT

    @staticmethod
    def UNIQUE_DST_24_SUBNETS_N(rec: pytrap.UnirecTemplate):
        """
        :param rec: Basic feature vector
        :return: Normalized count of unique /24 subnets by flow count
        """
        return rec.UNIQUE_DST_24_SUBNETS / rec.FLOW_COUNT

    @staticmethod
    def DURATION(rec: pytrap.UnirecTemplate):
        """
        Duration of observed attack
        :param rec: Basic feature vector
        :return: Duration of attack in seconds
        """
        duration = rec.POSIX_END - rec.POSIX_START
        if duration < 0:
            raise ValueError("Negative duration value")
        if duration == 0:
            duration = 1
        return duration

    @staticmethod
    def RATE(rec: pytrap.UnirecTemplate):
        """
        Rate of attack
        :param rec: Basi feature vector
        :return: Rate of attack in flows per second
        """
        return rec.FLOW_COUNT / DDoSClassifier.DURATION(rec)


class Geoip2Wrapper:
    """
    Wrapper for geoip city and ASN databases
    """

    def __init__(self, asn_db_path, city_db_path):
        """
        :param asn_db_path: Local ASN database file
        :param city_db_path: Local city database file
        """
        self.asn_db = geoip2.database.Reader(asn_db_path)
        self.city_db = geoip2.database.Reader(city_db_path)

    def get_asn(self, ip):
        """
        Get ASN information for IP address
        :param ip: IP adress
        :return: ASN
        """
        try:
            return self.asn_db.asn(ip)
        except geoip2.errors.AddressNotFoundError:
            return None

    def get_city(self, ip):
        """
        Geat city information for IP address
        :param ip: IP address
        :return: City information (name, latitude, longitude)
        """
        try:
            return self.city_db.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return None


def create_ddos_event(rec: pytrap.UnirecTemplate, geoip_db, victim_ip, domain, misp_templates_dir):
    """
    Create MISP event describing attack
    :param rec: Basic feature vector
    :param geoip_db: Geoip database wrapper
    :param victim_ip: Victim IP address
    :return: MISP event describing attack on victim IP
    """

    misp_event = MISPEvent(strict_validation=True)
    misp_event.analysis = MISP_ANALYSIS_COMPLETE
    misp_event.distribution = MISP_DIST
    misp_event.threat_level_id = MISP_THREAT
    misp_event.info = "Indirect DDoS detection via backscatter traffic analysis"
    # Taxonomies
    misp_event.add_tag('ecsirt:availability="ddos"')
    misp_event.add_tag('ddos:type="flooding-attack"')
    # Galaxies
    misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Network Denial of Service - T1498"')
    misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Endpoint Denial of Service - T1499"')

    # DDoS object and its attributes
    misp_ddos = MISPObject(name="ddos", strict=True, misp_objects_path_custom=misp_templates_dir)
    misp_ddos.add_attribute("domain-dst", domain)
    misp_ddos.add_attribute("ip-dst", str(victim_ip))
    if rec.PROTOCOL == TCP:
        misp_ddos.add_attribute("dst-port", rec.SRC_PORT_1)
    first_seen = datetime.fromtimestamp(rec.POSIX_START, LOCAL_TIMEZONE)
    last_seen = datetime.fromtimestamp(rec.POSIX_END, LOCAL_TIMEZONE)
    misp_ddos.add_attribute("first-seen", first_seen)
    misp_ddos.add_attribute("last-seen", last_seen)
    duration = DDoSClassifier.DURATION(rec) 
    misp_ddos.add_attribute("duration-of-service-malfunction", duration)
    # Location info
    city_info = geoip_db.get_city(victim_ip)
    if city_info is not None:
        misp_ddos.add_attribute('latitude', city_info.location.latitude)
        misp_ddos.add_attribute('longitude', city_info.location.longitude)

    est_bytes = int(rec.BYTES*SCALE_FACTOR) 
    est_flows = int(rec.FLOW_COUNT*SCALE_FACTOR) 
    est_packets = int(rec.PACKET_COUNT*SCALE_FACTOR)
    est_bps = int(est_bytes/duration)*8
    est_pps = int(est_packets/duration)
    misp_ddos.add_attribute('number-of-ddos-bytes', est_bytes)
    misp_ddos.add_attribute('number-of-ddos-flows', est_flows)
    misp_ddos.add_attribute('number-of-ddos-packets', est_packets)
    misp_ddos.add_attribute('total-bps', est_bps)
    misp_ddos.add_attribute('total-pps', est_pps)
    misp_ddos.add_attribute("protocol", PROTO_MAP[rec.PROTOCOL])
    misp_event.add_object(misp_ddos)

    # Add organization info 
    asn_info = geoip_db.get_asn(victim_ip)

    if asn_info is not None:
        if 'autonomous_system_organization' in asn_info.raw:
            misp_organization = MISPObject(name="organization", strict=True,
                                           misp_objects_path_custom=misp_templates_dir)
            misp_organization.add_attribute('name', asn_info.raw['autonomous_system_organization'])
            misp_organization.add_attribute('role', "Victim")
            misp_event.add_object(misp_organization)

    return misp_event


def process_arguments():
    parser = argparse.ArgumentParser(
        description="Classify backscatter vectors/events received from backscatter module into DDoS and non-DDoS "
                    "category and report them via MISP")
    parser.add_argument("--model", help="DDoS machine learning model.", type=argparse.FileType('rb'), required=True)
    parser.add_argument("--agp", help="ASN GeoIP2 database path.", required=True)
    parser.add_argument("--cgp", help="City GeoIP2 database path.", required=True)
    parser.add_argument("--url", help="URL to MISP instance.", required=True)
    parser.add_argument("--key", help="Automation MISP key.", required=True)
    parser.add_argument("--ssl", help="CA Bundle.", default=False)
    parser.add_argument("--logfile", help="Path and name of file used for logging.",
                        default='backscatter_classifier.log')
    parser.add_argument("--misp_templates_dir", help="Directory with MISP object templates.", required=True)
    parser.add_argument('--min_flows', help="Minimum number of flows in feature vector in order for event to be reported.", default=30, type=int)
    parser.add_argument('--min_threshold', help="Minimum classification threshold for event to be considered as "
                                                "DDoS. Threshold is real number in range (0,1), higher values results "
                                                "in less false positives.", type=float, default=0.99)
    parser.add_argument('--min_duration', help="Minimum duration of event in order to be reported, events below this"
                                               "value will not be reported.", default=30, type=int)
    parser.add_argument('--max_duration', help="Maximum duration of event in order to be reported,"
                                               "events above this value will not be reported.", default=7200, type=int)
    return parser.parse_known_args()


def main():

    # Process arguments and initialize TRAP interface
    try:
        args, _ = process_arguments()
    except SystemExit as e:
        args = None  # Error in arguments or help message

    trap = pytrap.TrapCtx()
    try:
        trap.init(sys.argv, 1, 0, module_name="Backscatter classifier common TRAP help")
        # Allow trap to print it's own help but terminate script anyway due to error in arguments
        if args is None:
            sys.exit(PYTHON_ARGS_ERROR_EXIT)
        trap.setRequiredFmt(0)
    except Exception as e:
        # Trap error message
        print(e)
        sys.exit(TRAP_ARGS_ERROR_EXIT)

    # Logging settings
    logger = logging.getLogger("backscatter_classifier")
    logging.basicConfig(level=logging.INFO, filename=args.logfile, filemode='w',
                        format="[%(levelname)s], %(asctime)s, %(name)s, %(funcName)s, line %(lineno)d: %(message)s")

    # ASN and city databases
    try:
        geoip_db = Geoip2Wrapper(args.agp, args.cgp)
    except Exception as e:
        logger.error(e)
        logger.error("Error while create GeoIP2 wrapper")
        print(str(e), file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    # MISP instance
    try:
        misp_instance = ExpandedPyMISP(args.url, args.key, args.ssl)
    except Exception as e:
        logger.error(e)
        logger.error("Error while creating MISP instance")
        print(str(e), file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    # DDoS model
    ddos_model = pickle.load(args.model)
    ddos_classifier = DDoSClassifier(ddos_model, args.min_threshold)

    # *** MAIN PROCESSING LOOP ***
    while True:
        try:
            # Receive data
            try:
                data = trap.recv()
            except pytrap.FormatChanged as e:
                # Automatically detect format
                fmttype, fmtspec = trap.getDataFmt(0)
                rec = pytrap.UnirecTemplate(fmtspec)
                data = e.data
            if len(data) <= 1:
                # Terminating message
                break

            # Decode received data into python object
            rec.setData(data)
    
            # Only Ipv4
            try:
                victim_ip = IPv4Address(rec.SRC_IP)
            except Exception as e:
                logger.info("Received IPv6 address, skipping")
                continue

            # Predict class of backscatter like traffic
            try:
                duration = DDoSClassifier.DURATION(rec)
                if duration < args.min_duration:
                    # attack is too short lived to be reported
                    continue
                if duration > args.max_duration:
                    # attack is too long
                    continue
                if rec.FLOW_COUNT < args.min_flows:
                    # attack does not have enough flows
                    continue
                for subnet in CESNET_NET:
                    if victim_ip in subnet:
                        continue
                ddos = ddos_classifier.predict(rec)
            except Exception as e:
                logger.error(e)
                continue

            # Report attack using MISP
            try:
                if ddos:
                    try:
                        domain = gethostbyaddr(str(victim_ip))
                    except herror as e:
                        # Do not report for unknown domains
                        continue
                    event = create_ddos_event(rec, geoip_db, victim_ip, domain[0], args.misp_templates_dir)
                    event_id = misp_instance.add_event(event)['Event']['id']
                    misp_instance.publish(event_id)

            except Exception as e:
                logger.error(str(e))
                continue
        except Exception as e:
            # Log and re-raise exception
            logger.error(e)
            raise e
    # *** END OF MAIN PROCESSING LOOP ***
    trap.finalize()


if __name__ == '__main__':
    main()
