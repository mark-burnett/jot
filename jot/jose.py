from .codec import base64url_encode
import abc
import json


__all__ = [
    'JOSEDictionary',
    'JOSEHeader',
    'JOSEObject',
    'JSONCompactSerializableMixin',
]


class JOSEObject(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def compact_serialize(self):  # pragma: no cover
        pass


class JSONCompactSerializableMixin(JOSEObject):
    def compact_serialize(self):
        return base64url_encode(json.dumps(self, separators=(',',':')))


class JOSEDictionary(dict, JSONCompactSerializableMixin): pass


class JOSEHeader(JOSEDictionary): pass
