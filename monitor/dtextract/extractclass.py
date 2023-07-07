import requests
import json

class ExtractApi() :

    def __init__(self, url, payload):
        self.url = url
        self.payload = payload

    def GetResponse(self) :
        return json.loads(requests.get(self.url, params=self.payload).text)
