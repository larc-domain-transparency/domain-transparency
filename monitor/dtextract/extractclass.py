import requests

class ExtractApi() :

    def __init__(self, url, payload):
        self.url = url
        self.payload = payload

    def GetResponse(self) :
        return requests.get(self.url, params=self.payload)