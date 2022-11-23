import json
import requests
import time
import pandas as pd
import csv

# target_group = "bugzilla.redhat.com"
# target_group = "bugzilla.redhat.com/bugzilla"
target_group = "bugzilla.mozilla.org"
bugzilla_show_bug_url = "https://{:s}/show_bug.cgi".format(target_group)
nvd_base_api = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
bugzilla_base_api = "https://{:s}/rest/bug/".format(target_group)

records_csv_file = "../result_data/cve_referred_{:s}_reports.csv".format(target_group)
start_index = 0
total_vul_num = 77000  # actual current value - 199186
vuln_num_each_req = 500
target_columns = {
    # bugzilla columns
    "bugzilla_id": str,
    "product": str,
    "component": str,
    "priority": str,
    "severity": str,
    "summary": str,
    "created": str,
    # ! "comment": str, # 暂时先不获取， 之后和nCBR一起获取
    # nvd_columns
    "nvd_index": str,
    "cve_id": int,
    "published": str,
    "description": str,
    "cwe": str,
    "cvss_v2_base": float,
    "cvss_v2_exploit": float,
    "cvss_v2_impact": float,
}


def get_via_api(rest_api, headers=None):
    for _ in range(5):
        try:
            resp = requests.get(rest_api, headers=headers)
            return resp
        except:
            time.sleep(10)
    return None


def get_bugzilla_id(refs):
    for ref in refs:
        # have the prefix uri of bugzilla bug page
        # FIXME: modify the judge method
        if ref.get("url").startswith(bugzilla_show_bug_url):
            return ref.get("url")[len(bugzilla_show_bug_url) + 4 :]

    # return -1 means this cve does not refer to bugzilla
    return None


def get_bugzilla_bug_info(bugzilla_bug_id, base_api=bugzilla_base_api):
    bugzilla_resp = get_via_api(base_api + bugzilla_bug_id)
    if bugzilla_resp.status_code >= 400:
        return None
    bugzilla_bug_info = json.loads(bugzilla_resp.text).get("bugs")[0]
    return bugzilla_bug_info


if __name__ == "__main__":
    #  using pandas to save data
    # including NVD columns, bugzilla report columns
    csv_f = open(records_csv_file, mode="a", newline="", encoding="utf-8")
    fw = csv.writer(csv_f)
    if start_index == 0:
        fw.writerow(target_columns.keys())
        csv_f.flush()

    while start_index < total_vul_num:
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print(
            "start to retrieve nvd records {:d} to {:d}".format(
                start_index, start_index + vuln_num_each_req - 1
            )
        )
        resp = get_via_api(
            nvd_base_api
            + "?startIndex={:d}&resultsPerPage={:d}".format(
                start_index, vuln_num_each_req
            ),
            headers={"apiKey": "80fb3521-d112-4e15-8c2d-bafd5c95ebe0"},
        )
        partial_vuln_list = json.loads(resp.text).get("vulnerabilities")
        for vuln in partial_vuln_list:
            start_index += 1

            bugzilla_bug_id = get_bugzilla_id(vuln.get("cve").get("references"))
            if bugzilla_bug_id is None:
                continue
            # get bugzilla details via bug id
            bugzilla_bug_info = get_bugzilla_bug_info(bugzilla_bug_id)
            if bugzilla_bug_info is None:
                continue
            # cur_row = pd.Series(index=target_columns.keys())
            cur_row = {}
            # bugzilla columns
            cur_row["bugzilla_id"] = bugzilla_bug_id
            cur_row["product"] = bugzilla_bug_info.get("product")
            cur_row["component"] = bugzilla_bug_info.get("component")[0]
            cur_row["priority"] = bugzilla_bug_info.get("priority")
            cur_row["severity"] = bugzilla_bug_info.get("severity")
            cur_row["summary"] = bugzilla_bug_info.get("summary")
            cur_row["created"] = bugzilla_bug_info.get("creation_time")

            # nvd columns
            cur_row["nvd_index"] = start_index
            cur_row["cve_id"] = vuln.get("cve").get("id")
            cur_row["published"] = vuln.get("cve").get("published")
            cur_row["description"] = vuln.get("cve").get("descriptions")[0].get("value")
            cur_row["cwe"] = (
                vuln.get("cve").get("weaknesses")[0].get("description")[0].get("value")
            )
            target_metric = "cvssMetricV2" if start_index < 190865 else "cvssMetricV31"
            cur_row["cvss_v2_base"] = (
                vuln.get("cve")
                .get("metrics")
                .get(target_metric)[0]
                .get("cvssData")
                .get("baseScore")
            )
            cur_row["cvss_v2_exploit"] = (
                vuln.get("cve")
                .get("metrics")
                .get(target_metric)[0]
                .get("exploitabilityScore")
            )
            cur_row["cvss_v2_impact"] = (
                vuln.get("cve").get("metrics").get(target_metric)[0].get("impactScore")
            )

            fw.writerow(cur_row.values())

    csv_f.close()
