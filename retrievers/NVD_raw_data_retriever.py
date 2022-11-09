import json, requests
import time

if __name__ == "__main__":
    base_api = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    start_index = 0
    total_vul_num = 200  # actual current value - 199186
    vuln_num_each_req = 50
    result_data = []
    while start_index < total_vul_num:
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
            )
        )
        partial_vuln_list = json.loads(resp.text).get("vulnerabilities")
        result_data.extend(partial_vuln_list)
        start_index += vuln_num_each_req

    result_file_name = "../result_data/NVD_raw.json"
    with open(result_file_name, "w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)
