import json, requests
import time

bugzilla_show_bug_url = 'https://bugzilla.redhat.com/show_bug.cgi'
nvd_base_api = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
bugzilla_base_api = 'https://bugzilla.redhat.com/rest/bug/'
start_index = 50000
total_vul_num = 50200  # actual current value - 199186
vuln_num_each_req = 50


def get_bugzilla_id(cve_obj):
    for ref in cve_obj.get('references'):
        # have the prefix uri of bugzilla bug page
        if ref.get('url').startswith(bugzilla_show_bug_url):
            return ref.get('url')[44:]

    # return -1 means this cve does not refer to bugzilla
    return None


if __name__ == '__main__':
    # retrieve cve data from nvd API
    result_data = []
    while start_index < total_vul_num:
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print('start to retrieve nvd records {:d} to {:d}'.format(start_index, start_index + vuln_num_each_req - 1))
        resp = requests.get(
            nvd_base_api + '?startIndex={:d}&resultsPerPage={:d}'.format(start_index, vuln_num_each_req))
        partial_vuln_list = json.loads(resp.text).get('vulnerabilities')
        for vuln in partial_vuln_list:
            bugziila_bug_id = get_bugzilla_id(vuln.get('cve'))
            if bugziila_bug_id is None:
                continue
            # get bugzilla details via bug id
            bugzilla_resp = requests.get(bugzilla_base_api + bugziila_bug_id)
            bugzilla_info = json.loads(bugzilla_resp.text).get('bugs')[0]
            # get bugzilla coments via bug id
            bugzilla_resp = requests.get(bugzilla_base_api + bugziila_bug_id + '/comment')
            bugzilla_comments = json.loads(bugzilla_resp.text).get('bugs').get(bugziila_bug_id).get('comments')
            # merge to nvd data
            vuln['bugzilla_comments'] = bugzilla_comments
            vuln['bugzilla_info'] = bugzilla_info
            # add to result list
            result_data.append(vuln)

        start_index += vuln_num_each_req

    # result json data
    result_file_name = '../result_data/referred_bugzilla_data.json'
    with open(result_file_name, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)
