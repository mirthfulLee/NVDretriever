# coding=uft-8
# * retriever target: 
# *
import json
import requests
import time
import csv

# import ijson
import re

target_columns = {
    # bugzilla columns
    "bugzilla_url": str,
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

nvd_json_file = "../result_data/NVD_filtered.json"
records_csv_file = "../result_data/all_platform_cve_bugzila_reports.csv"
# ! remember to change this start_index when start from the middle
start_index = 0


def get_via_api(rest_api, headers=None):
    for _ in range(3):
        try:
            resp = requests.get(rest_api, headers=headers)
            return resp
        except:
            time.sleep(5)
    return None


def get_bugzilla_bug_info(bugzilla_bug_id, base_api):
    url = base_api + bugzilla_bug_id
    bugzilla_resp = get_via_api(url)
    # * rest api 可能发生跳转 如 https://bugzilla.gnome.org/rest/bug/107025
    # * 可能未授权，如 https://bugzilla.mozilla.org/rest/bug/146244
    if (
        bugzilla_resp is None
        or bugzilla_resp.status_code >= 400
        or bugzilla_resp.url != url
    ):
        return None
    # ! the return text could be html for informing with status_code==200
    try:
        bugzilla_bug_info = json.loads(bugzilla_resp.text).get("bugs")[0]
        return bugzilla_bug_info
    except:
        return None


if __name__ == "__main__":
    #  using pandas to save data
    # including NVD columns, bugzilla report columns
    csv_f = open(
        records_csv_file,
        mode="a" if start_index > 0 else "w",
        newline="",
        encoding="utf-8",
    )
    fw = csv.writer(csv_f)
    with open(nvd_json_file, "r", encoding="utf-8") as json_f:
        nvd_records = json.load(json_f)[start_index:]
    if start_index == 0:
        fw.writerow(target_columns.keys())
        csv_f.flush()

    for i, nvd_record in enumerate(nvd_records):
        cur_index = start_index + i
        if i % 100 == 0:
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            print("start to retrieve nvd record-{:d}".format(cur_index))
        for ref in nvd_record.get("references"):
            ref_url = ref.get("url")
            # ! there might be a "/bugzilla3?" before show_bug.cgi
            simplified_ref = re.sub(r"/bugzilla3?/show_bug", "/show_bug", ref_url)
            simplified_ref = simplified_ref.replace("http://", "https://")
            if "bugzilla" not in simplified_ref or "show_bug.cgi" not in simplified_ref:
                continue
            # * show_bug_url_pattern = r"^https?://bugzilla.*/show_bug.cgi\?id=.+"
            # * replace_pattern = r"/bugzilla/show_bug.cgi" -> r"/show_bug.cgi"
            ref_domain = re.search(
                r"^https?://bugzilla.*(?=/show_bug)", simplified_ref
            ).group(0)
            bugzilla_bug_id = re.search(
                r"(?<=/show_bug.cgi\?id=).+", simplified_ref
            ).group(0)

            # get bugzilla details via bug id
            bugzilla_bug_info = get_bugzilla_bug_info(
                bugzilla_bug_id, ref_domain + "/rest/bug/"
            )
            if bugzilla_bug_info is None:
                print("****  fail to get bugzilla report via url  ****")
                print(simplified_ref)
                continue
            cur_row = {}
            # bugzilla columns
            cur_row["bugzilla_id"] = bugzilla_bug_info.get("id")
            cur_row["bugzilla_url"] = ref_domain
            cur_row["product"] = bugzilla_bug_info.get("product")
            cur_row["component"] = bugzilla_bug_info.get("component")[0]
            cur_row["priority"] = bugzilla_bug_info.get("priority")
            cur_row["severity"] = bugzilla_bug_info.get("severity")
            cur_row["summary"] = bugzilla_bug_info.get("summary")
            cur_row["created"] = bugzilla_bug_info.get("creation_time")

            # nvd columns
            cur_row["nvd_index"] = nvd_record.get("nvd_index")
            cur_row["cve_id"] = nvd_record.get("cve_id")
            cur_row["published"] = nvd_record.get("published")
            cur_row["description"] = nvd_record.get("description")
            cur_row["cwe"] = nvd_record.get("cwe")
            cur_row["cvss_v2_base"] = nvd_record.get("cvss_v2_base")
            cur_row["cvss_v2_exploit"] = nvd_record.get("cvss_v2_exploit")
            cur_row["cvss_v2_impact"] = nvd_record.get("cvss_v2_impact")

            fw.writerow(cur_row.values())

    csv_f.close()
