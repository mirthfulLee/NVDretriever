import json
import requests
import time

if __name__ == "__main__":
    base_api = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    start_index = 0
    total_vul_num = 199000  # actual current value - 199186
    vuln_num_each_req = 500
    result_file_name = "../result_data/NVD_raw.json"

    json_file = open(result_file_name, "a", encoding="utf-8")
    if start_index == 0:
        json_file.write("[")
    while start_index < total_vul_num:
        # nvd_columns
        # "nvd_index": str,
        # "cve_id": int,
        # "published": str,
        # "description": str,
        # "cwe": str,
        # "cvss_v2_base": float,
        # "cvss_v2_exploit": float,
        # "cvss_v2_impact": float,
        # "references": list
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print(
            "start to retrieve records {:d} to {:d}".format(
                start_index, start_index + vuln_num_each_req - 1
            )
        )
        resp = requests.get(
            base_api
            + "?startIndex={:d}&resultsPerPage={:d}".format(
                start_index, vuln_num_each_req
            ),
            headers={"apiKey": "80fb3521-d112-4e15-8c2d-bafd5c95ebe0"},
        )
        partial_vuln_list = json.loads(resp.text).get("vulnerabilities")
        for vuln in partial_vuln_list:
            cur_row = {}
            start_index += 1
            if vuln.get("cve").get("vulnStatus") == "Rejected":
                continue

            cur_row["nvd_index"] = start_index
            cur_row["cve_id"] = vuln.get("cve").get("id")
            cur_row["published"] = vuln.get("cve").get("published")
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
            cur_row["description"] = vuln.get("cve").get("descriptions")[0].get("value")
            cur_row["references"] = vuln.get("cve").get("references")

            json.dump(cur_row, json_file, ensure_ascii=False)
            json_file.write(",\n" if start_index < total_vul_num else "]")

        json_file.flush()

    json_file.close()
