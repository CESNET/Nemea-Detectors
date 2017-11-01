# Class for basic flow without SMTP Headers
class Flow:
    def __init__(self, rec):
        # Basic flow
        self.DST_IP = rec.DST_IP
        self.SRC_IP = rec.SRC_IP
        self.BYTES = rec.BYTES
        self.TIME_FIRST = rec.TIME_FIRST
        self.TIME_LAST = rec.TIME_LAST
        self.PACKETS = rec.PACKETS
        self.DST_PORT = rec.DST_PORT
        self.SRC_PORT = rec.SRC_PORT
        self.TCP_FLAGS = rec.TCP_FLAGS

    def __repr__(self):
        return "SRC_IP:" + self.SRC_IP + ",DST_IP:" + self.DST_IP + ",BYTES:" \
                 + self.BYTES + ",TIME_FIRST;" + self.TIME_FIRST + ",TIME_LAST:" \
                 + self.TIME_LAST + ",PACKETS:" + self.PACKETS

