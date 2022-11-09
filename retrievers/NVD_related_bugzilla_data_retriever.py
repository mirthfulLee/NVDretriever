import json
import requests
import time
from collections import defaultdict

bugzilla_show_bug_url = "https://bugzilla.redhat.com/show_bug.cgi"
nvd_base_api = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
bugzilla_base_api = "https://bugzilla.redhat.com/rest/bug/"
start_index = 40000
total_vul_num = 40500  # actual current value - 199186
vuln_num_each_req = 50


def get_bugzilla_id(cve_obj):
    for ref in cve_obj.get("references"):
        # have the prefix uri of bugzilla bug page
        if ref.get("url").startswith(bugzilla_show_bug_url):
            return ref.get("url")[44:]

    # return -1 means this cve does not refer to bugzilla
    return None


def get_bugzilla_bug_info(bugzilla_bug_id, base_api=bugzilla_base_api):
    bugzilla_resp = requests.get(base_api + bugzilla_bug_id)
    bugzilla_bug_info = json.loads(bugzilla_resp.text).get("bugs")[0]
    return bugzilla_bug_info


def get_bugzilla_bug_comments(bugzilla_bug_id, base_api=bugzilla_base_api):
    bugzilla_resp = requests.get(base_api + bugzilla_bug_id + "/comment")
    bugzilla_bug_comments = (
        json.loads(bugzilla_resp.text).get("bugs").get(bugzilla_bug_id).get("comments")
    )
    return bugzilla_bug_comments


if __name__ == "__main__":
    # retrieve cve data from nvd API
    # meanwhile analysis involved product (product_name: CVE_num)
    result_data = []
    product_cir_cnt = defaultdict(int)
    while start_index < total_vul_num:
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print(
            "start to retrieve nvd records {:d} to {:d}".format(
                start_index, start_index + vuln_num_each_req - 1
            )
        )
        # TODO: retry requests for 5 times if the the previous request crashed
        resp = requests.get(
            nvd_base_api
            + "?startIndex={:d}&resultsPerPage={:d}".format(
                start_index, vuln_num_each_req
            )
        )
        partial_vuln_list = json.loads(resp.text).get("vulnerabilities")
        for vuln in partial_vuln_list:
            bugzilla_bug_id = get_bugzilla_id(vuln.get("cve"))
            if bugzilla_bug_id is None:
                continue
            # get bugzilla details via bug id
            bugzilla_bug_info = get_bugzilla_bug_info(bugzilla_bug_id)
            product_name = bugzilla_bug_info.get("product")
            product_cir_cnt[product_name] += 1

            # get bugzilla coments via bug id
            bugzilla_bug_comments = get_bugzilla_bug_comments(bugzilla_bug_id)

            # merge to nvd data
            vuln["bugzilla_bug_comments"] = bugzilla_bug_comments
            vuln["bugzilla_bug_info"] = bugzilla_bug_info
            # add to result list
            result_data.append(vuln)

        start_index += vuln_num_each_req

    # save result json data
    result_file_name = "../result_data/referred_bugzilla_data.json"
    with open(result_file_name, "w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)

    # save product cir cnt result
    product_cir_cnt_file = "../result_data/product_CIR_num.json"
    with open(product_cir_cnt_file, "w", encoding="utf-8") as f:
        json.dump(product_cir_cnt, f, indent=2, ensure_ascii=False)
