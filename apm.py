import random


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.key_pages = []
        self.timespan_entries = []
        self.fn_arg_entries = []


config = ApmConfig()


def trigger_trace():
    return config.sample_rate >= random.random()


def trigger_extended_trace():
    return config.extended_sample_rate >= random.random()
