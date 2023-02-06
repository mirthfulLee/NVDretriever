# coding=utf-8
# * target:
# * 1. filter the Security Responce
# * 2. analyse the involved product
# * 3. unify the id to bugzilla id (number)
# * 4. compress the SBR content

import pandas as pd
import json
import re
import requests
import time


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
    records_csv_file = "../result_data/all_platform_cve_bugzila_reports.csv"
    product_info_file = "../result_data/product_info.csv"
    br_process_file = "../result_data/BR_process.csv"
    description_process_file = "../result_data/description_process.csv"
    filtered_SBR_file = "../result_data/SBR.csv"

    bz_records = pd.read_csv(records_csv_file, header=0)

    # ! filter product = "Security Response"
    bz_records = bz_records.loc[bz_records["product"] != "Security Response"]
    # sort by product
    bz_records = bz_records.sort_values(by="product", ignore_index=True)

    # # ! filter BRs disclosed before being created
    # bz_records = bz_records.loc[
    #     bz_records.apply(lambda x: x["created"][:13] < x["published"][:13], axis=1)
    # ]

    # ! analyse the involved product
    product_cnt = bz_records.drop_duplicates(subset=["product"], ignore_index=True)
    product_cnt["bugzilla_domain"] = product_cnt.apply(
        lambda row: re.search(
            r"^https?://bugzilla.*(?=/show_bug)", row["bugzilla_url"]
        ).group(0),
        axis=1,
    )
    product_cnt = product_cnt.loc[:, ["product", "bugzilla_domain"]].sample(frac=1)
    product_cnt = product_cnt.sort_values(by="product", ignore_index=True)
    print(product_cnt)
    product_cnt.to_csv(product_info_file, header=True, index=False)
    # * add offset column to enable the retriever to get data from the failure position
    product_cnt["offset"] = 0
    product_cnt.to_csv(br_process_file, header=True, index=False)
    product_cnt.to_csv(description_process_file, header=True, index=False)

    # ! unify the id to bugzilla id (number)
    bz_records.insert(0, "bugzilla_id", 0)
    for i, row in bz_records.iterrows():
        bugzilla_id = re.search(
            r"(?<=/show_bug.cgi\?id=).+", row["bugzilla_url"]
        ).group(0)
        if not bugzilla_id.isdigit():
            print(row["bugzilla_url"])
            ref_domain = re.search(
                r"^https?://bugzilla.*(?=/show_bug)", row["bugzilla_url"]
            ).group(0)
            # get bugzilla details via bug id
            bugzilla_bug_info = get_bugzilla_bug_info(
                bugzilla_id, ref_domain + "/rest/bug/"
            )
            bugzilla_id = str(bugzilla_bug_info.get("id"))
        bz_records.at[i, "bugzilla_id"] = bugzilla_id

    # ! compress the SBR content
    bz_records.drop(["bugzilla_url"], axis=1, inplace=True)
    bz_records.to_csv(filtered_SBR_file, header=True, index=False)
