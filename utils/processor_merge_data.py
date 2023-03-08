import pandas as pd
import json
import os
import random

# 1. github IR: all_sample_processed.csv => all_sample_processed.json
# 2. bugzilla BR: csv files => bugzilla_reports.json
# 3. merge two json
# 4. split data to training_samples.json, validation..testing..
# 5. transform training_samples.json to txt fpr MLM pretraining


def list_to_json(str_list, json_file):
    with open(json_file, "w", encoding="utf-8") as f:
        f.write("\n".join(str_list))


def get_cve_id(SBR_info, product, bugzilla_id):
    row = SBR_info[
        SBR_info["product" == product and SBR_info["bugzilla_id"] == bugzilla_id]
    ]
    return row.iloc[0, :]["CVE_id"]


def merge_csv_data_to_json():
    merged_result_file = os.path.join(data_root, "bugzilla_all_samples.json")
    product_info_file = os.path.join(data_root, "product_info.csv")
    product_info = pd.read_csv(product_info_file)
    SBR_file = os.path.join(data_root, "SBR_processed.csv")
    SBR_info = pd.read_csv(SBR_file)
    records = []
    for _, product_row in product_info.iterrows():
        product = product_row["product"]
        domain = product_row["bugzilla_domain"]
        partial_sbr = SBR_info[SBR_info["product"] == product]
        reports_file = os.path.join(
            data_root, "BR_complete_processed", product.replace("/", "_") + ".csv"
        )

        reports = pd.read_csv(
            reports_file,
            usecols=[
                "bugzilla_id",
                "summary",
                "created",
                "text",
            ],
        )
        reports.rename(
            columns={
                "bugzilla_id": "Issue_Url",
                "created": "Issue_Created_At",
                "summary": "Issue_Title",
                "text": "Issue_Body",
            },
            inplace=True,
        )
        reports["Security_Issue_Full"] = 0
        reports["CVE_ID"] = ""
        reports["Published_Date"] = ""
        for _, sbr_row in partial_sbr.iterrows():
            br_index = reports[sbr_row["bugzilla_id"] == reports["Issue_Url"]].index[0]
            reports.at[br_index, "Security_Issue_Full"] = 1
            reports.at[br_index, "CVE_ID"] = sbr_row["cve_id"]
            reports.at[br_index, "Published_Date"] = sbr_row["published"]

        reports["Issue_Url"] = reports.apply(
            lambda x: "{}/show_bug.cgi?id={}".format(domain, x["Issue_Url"]),
            axis=1,
        )
        # *filter rows that Issue_Created_At > Published_Date
        reports = reports[
            (reports["Published_Date"] == "")
            | (reports["Issue_Created_At"] < reports["Published_Date"])
        ]
        if (reports["Security_Issue_Full"] == 0).all():
            print("{} does not have valid SBR, drop all reports!!".format(product))
            continue

        records = records + reports.to_dict(orient="records")

    # *save df to json file
    with open(merged_result_file, "w") as jf:
        json.dump(records, jf, indent=4)


def split_two_json_file():
    bugzilla_json_file = os.path.join(data_root, "bugzilla_all_samples.json")
    github_json_file = os.path.join(data_root, "bugzilla_all_samples.json")
    train_file = os.path.join(data_root, "train_samples.json")
    validation_file = os.path.join(data_root, "validation_samples.json")
    test_file = os.path.join(data_root, "test_samples.json")

    bugzilla_reports = json.load(open(bugzilla_json_file, "r"))
    github_reports = json.load(open(github_json_file, "r"))

    reports = bugzilla_reports + github_reports
    random.shuffle(reports)
    reports_num = len(reports)

    with open(train_file, "w", encoding="utf-8") as f:
        json.dump(
            reports[: int(0.8 * reports_num)],
            f,
            indent=4,
        )
    with open(validation_file, "w", encoding="utf-8") as f:
        json.dump(
            reports[int(0.8 * reports_num) : int(0.9 * reports_num)],
            f,
            indent=4,
        )
    with open(test_file, "w", encoding="utf-8") as f:
        json.dump(
            reports[int(0.9 * reports_num) :],
            f,
            indent=4,
        )


def generate_dataset_mlm():
    # generate the trainset for run_mlm_wwm.py (further pretraining BERT)
    # each line corresponds to a issue reprot
    reports = json.load(open(os.path.join(data_root, "train_samples.json"), "r"))
    print(len(reports))
    mlm_file = os.path.join(data_root, "train_project_mlm.txt")
    f = open(mlm_file, "w", encoding="utf-8")
    for report in reports:
        f.write(f"{report['Issue_Title']}. {report['Issue_Body']}\n")
    f.close()


data_root = "../result_data/"

if __name__ == "__main__":
    # merge_csv_data_to_json()
    # split_two_json_file()
    generate_dataset_mlm()
