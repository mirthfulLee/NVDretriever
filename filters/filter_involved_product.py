import pandas as pd
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
    "cve_id": str,
    "published": str,
    "description": str,
    "cwe": str,
    "cvss_v2_base": float,
    "cvss_v2_exploit": float,
    "cvss_v2_impact": float,
}

if __name__ == "__main__":
    records_csv_file = "../result_data/all_platform_cve_bugzila_reports.csv"
    result_file = "../result_data/des_product_info.csv"
    bz_records = pd.read_csv(records_csv_file, header=0, dtype=target_columns)

    # * filter Security Response
    bz_records = bz_records.loc[bz_records["product"] != "Security Response"]
    # * sort by product
    bz_records = bz_records.sort_values(by="product", ignore_index=True)

    print(bz_records.shape[0])

    product_cnt = bz_records.drop_duplicates(subset=["product"], ignore_index=True)
    product_cnt["bugzilla_domain"] = product_cnt.apply(
        lambda row: re.search(
            r"^https?://bugzilla.*(?=/show_bug)", row["bugzilla_url"]
        ).group(0),
        axis=1,
    )
    product_cnt = product_cnt.loc[:, ["product", "bugzilla_domain"]].sample(frac=1)
    # ! add offset column to enable the retriever to get data from the failure position
    product_cnt["offset"] = 0
    print(product_cnt)
    product_cnt.to_csv(result_file, header=True, index=False)
