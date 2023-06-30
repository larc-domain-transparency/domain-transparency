import ExtractApi from extractclass

def get-smh() :
    url='http://127.0.0.1:8021/dt/v1/get-smh'
    payload={}

    return ExtractApi(url, payload).GetResponse()

    
def get-domain-root-and-proof(domain_name) :
    url='http://127.0.0.1:8021/dt/v1/get-domain-root-and-proof'
    payload={
        "domain_name" : domain_name,
        "domain_map_size" : 563
    }

    return ExtractApi(url, payload).GetResponse()

def consistency-proof(domain_name) :
    url='http://127.0.0.1:8021/dt/v1/get-consistency-proof'
    payload={
        "domain_name" : domain_name,
        "first" : 2,
        "second" : 20
    }

    return ExtractApi(url, payload).GetResponse()

def entry-and-proof(domain_name) :
    url='http://127.0.0.1:8021/dt/v1/get-consistency-proof'
    payload={
        "domain_name" : domain_name,
        "index" : 2,
        "domain_tree_size" : 20
    }

    return ExtractApi(url, payload).GetResponse()

def entry() :

    api = ExtractApi(url, payload)

    return api.GetResponse()

def get-domain-tree-index() :

    api = ExtractApi(url, payload)

    return api.GetResponse()

def get-source-logs() :

    api = ExtractApi(url, payload)

    return api.GetResponse()

def get-source-log-and-proof() :

    api = ExtractApi(url, payload)

    return api.GetResponse()

def get-source-logs() :

    api = ExtractApi(url, payload)

    return api.GetResponse()

