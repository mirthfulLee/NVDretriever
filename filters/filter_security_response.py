import pandas as pd
import re

records_csv_file = "../result_data/all_platform_cve_bugzila_reports.csv"
result_file = "../result_data/filtered_CBR.csv"
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

    # * filter Security Response
    bz_records = bz_records.loc[bz_records["product"] != "Security Response"]
    # * sort by product
    bz_records = bz_records.sort_values(by="product", ignore_index=True)

    print(bz_records.shape[0])

    # ! 筛掉发布时间比创建时间早的bug report
    bz_records = bz_records.loc[
        bz_records.apply(lambda x: x["created"][:13] < x["published"][:13], axis=1)
    ]
    print(bz_records.shape[0])
    bz_records.to_csv(result_file, header=True, index=False)
