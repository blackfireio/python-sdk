class BlackfireApiException(Exception):
    pass


class BlackfireProfilerException(Exception):
    pass


class BlackfireAPMException(Exception):
    pass


class BlackfireAPMStatusFalseException(BlackfireAPMException):
    pass


class BlackfireInvalidSignatureError(Exception):
    pass
