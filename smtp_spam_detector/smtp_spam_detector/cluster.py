#!/usr/env python

class Cluster:
    def __init__(self):
        self.cluster_nodes = []

    def clustering(self, data_pool):
        """data_pool dict(SRC_IP)"""
        print("Started clustering.\n")

        # iteration through all recorded servers
        for ip in data_pool:
            server = data_pool[ip]
            added = False

            for cluster in self.cluster_nodes:
                if (is_similar(server, cluster)):
                    cluster.append(server)
                    added = True
                    break

            if not added:
                # add new group/cluster with only one server
                self.cluster_nodes.append([server])

    def __str__(self):
        cnt = 0
        ret = "************************************************************\n"
        ret += "Clustering report:\n"
        ret += "Number of clusters: " + str(len(self.cluster_nodes)) + "\n"

        for i in self.cluster_nodes:
            ret += "Node: " + str(cnt) + "\n"
            for q in i:
                ret += "\tServer IP: " + str(q.id) + "\n"
                for j in q.sent_history:
                    ret += "\t\t" + j.SMTP_FIRST_SENDER + "\n"

            cnt += 1
        return ret

class ClusterNode:
    def __init__(self):
        self.common_index = ""
        self.cluster_data = list()

    # Setter for the most common index
    def setCommonIndex(self):
        return None
