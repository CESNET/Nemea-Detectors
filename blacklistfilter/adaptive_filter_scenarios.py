
import time

IP_IF = 0
URL_IF = 1

# Thrown by Scenario subclass' init function when the detection flow doesn't
# fit the scenario
class ScenarioDoesNotFit:
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


class Scenario:
    def __init__(self, detection_flow: tuple):
        self.detection_flow = detection_flow
        self.ts = time.time()


class BotnetDetecion(Scenario):
    def __init__(self, detection_flow):
        super().__init__(detection_flow)

        if self.detection_flow[0] == IP_IF:
            print('is from IP detector')
        else:
            raise ScenarioDoesNotFit


class DNSDetection(Scenario):
    def __init__(self, detection_flow):
        super().__init__(detection_flow)
        print('I am DNSDetection')
        raise ScenarioDoesNotFit