import pandas as pd
import os
import csv
import retriever_bugzilla_description as bzd
import retriever_bugzilla_report_info as bzi
from processor_for_bugzilla_reports import replace_tokens_simple

if __name__ == "__main__":
    product_info_file = "../result_data/product_info.csv"
    SBR_file = "../result_data/SBR.csv"
    br_dir = "../result_data/BR_complete"
    br_processed_dir = "../result_data/BR_complete_processed"

    product_info = pd.read_csv(product_info_file)
    SBR_info = pd.read_csv(SBR_file)
    logger = bzd.get_logger("SBR_process", "../logs/SBR_process.log")

    for _, product_row in product_info.iterrows():
        product = product_row["product"]
        domain = product_row["bugzilla_domain"]
        logger.info("Start the process of {} ..".format(product))
        product_file_name = product.replace("/", "_") + ".csv"
        file_with_description = os.path.join(br_dir, product_file_name)
        file_processed = os.path.join(br_processed_dir, product_file_name)

        # init file writer
        existing_BR_ids = pd.read_csv(file_with_description, usecols=["bugzilla_id"])
        f_desc = open(file_with_description, mode="a", newline="", encoding="utf-8")
        desc_fw = csv.writer(f_desc)
        f_processed = open(file_processed, mode="a", newline="", encoding="utf-8")
        processed_fw = csv.writer(f_processed)

        existing_BR_ids = existing_BR_ids["bugzilla_id"].to_list()
        product_SBR = SBR_info[SBR_info["product"] == product]

        for _, report in product_SBR.iterrows():
            bugzilla_id = report["bugzilla_id"]
            if bugzilla_id in existing_BR_ids:
                continue
            # TODO: get BR info
            url = domain + "/rest/bug/" + str(bugzilla_id)
            report_infos = bzi.get_bug_infos(url, logger)
            if report_infos is None or len(report_infos) == 0:
                logger.error("fail to get report info from {}".format(url))
                continue
            report_info = report_infos[0]

            # TODO: get BR description
            report_comments = bzd.get_comments_of_bug(domain, str(bugzilla_id), logger)
            if report_comments is None or len(report_comments) == 0:
                logger.error(
                    "fail to get report description from {}".format(
                        "{}/rest/bug/{}/comment".format(domain, bugzilla_id)
                    )
                )
                continue
            report_desc = report_comments[0]

            # TODO: add to BR_complete
            cur_row = {}
            # bugzilla columns
            cur_row["bugzilla_id"] = report_info.get("id")
            cur_row["product"] = report_info.get("product")
            cur_row["component"] = report_info.get("component")
            cur_row["priority"] = report_info.get("priority")
            cur_row["severity"] = report_info.get("severity")
            cur_row["summary"] = report_info.get("summary")
            cur_row["created"] = report_info.get("creation_time")
            cur_row["description_id"] = report_desc["id"]
            cur_row["text"] = report_desc["text"]
            cur_row["is_private"] = report_desc["is_private"]
            desc_fw.writerow(cur_row.values())

            # TODO: preprocess BR title, text and add to BR_complete_processed
            cur_row["summary"] = replace_tokens_simple(cur_row["summary"])
            cur_row["text"] = replace_tokens_simple(cur_row["text"])
            cur_row["security_relevent"] = True
            processed_fw.writerow(cur_row.values())
