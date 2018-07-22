
from time import time

IP_IF = 0
URL_IF = 1

# Thrown by Scenario subclass' init function when the detection flow doesn't
# fit the scenario
class ScenarioDoesNotFit(BaseException):
    def __init__(self, expression=None, message=None):
        self.expression = expression
        self.message = message


class Scenario:
    # TODO: What if the program dies, maybe random string/int instead?
    id = 1

    def __init__(self, detection_flow):
        self.detection_flow = detection_flow
        self.detection_cnt = 0
        self.first_ts = time()
        self.last_ts = time()
        self.id = Scenario.id
        self.adaptive_entities = []

    def set_id(self):
        self.id = Scenario.id
        Scenario.id += 1


class BotnetDetection(Scenario):
    def __init__(self, detection_iface, detection_flow):
        super().__init__(detection_flow)
        self.key = (detection_flow.SRC_IP, detection_flow.DST_IP)

        if detection_iface != IP_IF:
            raise ScenarioDoesNotFit

        # TODO: if type == C&C


    def generate_entities(self):
        # Suffix for the adaptive filter (blacklist_idx, scenario_id)
        # TODO: Number of adaptive blacklist id?
        suffix = ',{},{}'.format(99, self.id)
        # Add entity which was NOT on the blacklist
        if self.detection_flow.DST_BLACKLIST:

            self.adaptive_entities.append(str(self.detection_flow.SRC_IP) + suffix)
        else:
            self.adaptive_entities.append(str(self.detection_flow.DST_IP) + suffix)


class DNSDetection(Scenario):
    def __init__(self, detection_iface, detection_flow):
        super().__init__(detection_flow)
        raise ScenarioDoesNotFit