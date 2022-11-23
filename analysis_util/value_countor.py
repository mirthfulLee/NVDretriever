import pandas as pd
import re

records_csv_file = "../result_data/all_platform_cve_bugzila_reports.csv"
result_file = "../result_data/temporary_records_for_analyse.csv"
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
    "cve_id": str,
    "published": str,
    "description": str,
    "cwe": str,
    "cvss_v2_base": float,
    "cvss_v2_exploit": float,
    "cvss_v2_impact": float,
}

if __name__ == "__main__":
    bz_records = pd.read_csv(records_csv_file, header=0, dtype=target_columns)
    bz_records["domain"] = bz_records["bugzilla_url"].apply(
        lambda x: re.search(r"(?<=https://)bugzilla.*(?=/show_bug)", x).group(0)
    )

    # print(bz_records["domain"].value_counts())
    print(bz_records.value_counts("product").size)
    bz_records = bz_records.groupby("domain")
    groups = bz_records.groups
    for g in groups.keys():
        cnt_result = bz_records.get_group(g)["product"].value_counts()
        print(
            "*****{:s} has {:d} products with {:d} CIR:".format(
                g, cnt_result.size, cnt_result.sum()
            )
        )
        print(cnt_result.head(10))
