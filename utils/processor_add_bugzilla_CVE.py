# add CVE records of bugzilla to CVE_dict.json
import pandas as pd
import json
import os

# "CVE-1999-0159": {
#     "CVE_ID": "CVE-1999-0159",
#     "Published_Date": "1998-08-12T04:00Z",
#     "Modified_Date": "2008-09-09T12:33Z",
#     "CVE_Description": "Attackers can crash a Cisco IOS router or device, provided they can get to an interactive prompt (such as a login).  This applies to some IOS 9.x, 10.x, and 11.x releases.",
#     "Severity": "MEDIUM",
#     "Exploitability_Score": "10.0",
#     "Impact_Score": "2.9",
#     "CWE_ID": "NVD-CWE-Other",
#     "References_String": null
# }
# ...severity,summary,created,nvd_index,cve_id,published,description,cwe,cvss_v2_base,cvss_v2_exploit,cvss_v2_impact


def add_records_json():
    bugzilla_records = pd.read_csv(bugzilla_cve_file)
    cve_dict = json.load(open(cve_dict_file, "r"))
    for i, bugzilla_cve in bugzilla_records.iterrows():
        cve_id = bugzilla_cve["cve_id"]
        if not cve_dict.__contains__(cve_id):
            record = {}
            record["CVE_ID"] = cve_id
            record["Published_Date"] = bugzilla_cve["published"]
            record["Modified_Date"] = "later than" + bugzilla_cve["published"]
            record["CVE_Description"] = bugzilla_cve["description"]
            record["Severity"] = bugzilla_cve["severity"]
            record["Exploitability_Score"] = bugzilla_cve["cvss_v2_exploit"]
            record["Impact_Score"] = bugzilla_cve["cvss_v2_impact"]
            record["CWE_ID"] = bugzilla_cve["cwe"]
            record["References_String"] = "Bugzilla - " + bugzilla_cve["product"]
            cve_dict[cve_id] = record
    # *save df to json file
    with open(merged_dict_file, "w") as jf:
        json.dump(cve_dict, jf, indent=4)


if __name__ == "__main__":
    data_root = "../result_data"
    cve_dict_file = os.path.join(data_root, "CVE_dict.json")
    merged_dict_file = os.path.join(data_root, "CVE_dict_merged.json")
    bugzilla_cve_file = os.path.join(data_root, "SBR_processed.csv")
    add_records_json()
