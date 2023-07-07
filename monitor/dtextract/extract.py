from extractclass import ExtractApi
import json 

def test() :
    print("Worked!")

def get_smh() :
    url='http://127.0.0.1:8021/dt/v1/get-smh'
    payload={}

    return ExtractApi(url, payload).GetResponse()

def get_domain_entries(domain_name) :
    # it returns only the index of the domain_name given for log server 0
    url='http://127.0.0.1:8021/dt/v1/get-entries' 
    payload={ # for now range of 20
        'domain_name': domain_name, 
        'start': 0, 
        'end':20
    }

    return [item[1] for item in ExtractApi(url, payload).GetResponse()['entries']]

def get_domain_certificates(domain_entries) :
    # it returns a list of domain certificates with their domain entry, the leaf input and some extra data 
    url='http://127.0.0.1:6962/demo-log/ct/v1/get-entries'
    domain_certificates = []

    for domain_entry in domain_entries :
        certificates_data = []
        certificates_data.append(domain_entry) # push domain entry

        payload={ 
            'start': domain_entry, 
            'end': domain_entry
        }
        certificate_info = ExtractApi(url, payload).GetResponse()

        certificates_data.append(certificate_info['entries'][0]['leaf_input']) # push left input
        certificates_data.append(certificate_info['entries'][0]['leaf_input']) # push extra data

        domain_certificates.append(certificates_data)

    return domain_certificates

# test()
# obj = get_domain_entries('example-1.com')
# print(len(obj))
# print(type(obj))
# print(get_domain_certificates(obj))


